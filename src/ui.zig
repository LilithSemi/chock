//! The interface bare `chock` brings up, and the one seam it is built on.
//!
//! ## Which command this is, and which it is not
//!
//! **`chock`, with no command, is the interface.** It used to print the usage
//! page, and it still does when nothing can be drawn.
//!
//! **`chock run` is the plain command line and gains nothing here.** It writes
//! lines, it paints them, and that is all it has ever done. `Options.interface`
//! in `src/run.zig` is what the two share, and `parseOptions` never sets it, so
//! no command line can turn a display on inside `chock run`.
//!
//! ## Which backend, and who decides
//!
//! **Chock asks one question and answers none of the others.** The question is
//! whether there is anything to draw on, which is about the environment this
//! process was started in. Everything below it belongs to the stack:
//!
//! * **Phantom** picks the backend: `phantom.app.selectBackend` reads
//!   `PHANTOM_BACKEND`, then `WAYLAND_DISPLAY`, then `DISPLAY`, then whether
//!   standard output is a terminal, and it is what excludes the window on a
//!   target that has none.
//! * **Lattice** owns the window.
//! * **Prism** owns the drawing, GPU or software.
//!
//! **So there is no platform test in this file**, and there must not be one. A
//! machine with no compositor, no GPU, or neither is answered above this and not
//! here.
//!
//! `decide` turns phantom's answer into what Chock draws on:
//!
//! * **`.gpu` is a window.** Lattice is asked for a screen and for a keyboard,
//!   and prism for a frame, so this is an answer and not a guess. See
//!   `windowPossible`, which says why one of those three is not enough.
//! * **`.tui` is the terminal.**
//! * **`.none` is the usage page**, unchanged. Somebody running `chock | head`
//!   or `chock > notes` in a script must not meet a full screen application, and
//!   the usage page is what that caller already gets.
//!
//! A terminal that says `TERM=dumb`, or says nothing at all, is the usage page
//! too. That is the one part of the question the stack does not answer:
//! `selectBackend` reads the descriptor and never `TERM`. See
//! `tty.terminalCanDraw`, which is the one place that rule lives.
//!
//! **One widget tree serves both backends.** Phantom splits them the same way,
//! `init`, `step`, `deinit`, so `Surface` is a union of two pointers and three
//! one line methods: see it for what the two genuinely do not share.
//!
//! **Colour is not part of that decision.** `NO_COLOR` and `--color=never` say
//! no colour, not no interface, so the display is drawn with `ColorMode.none`
//! and carries no SGR at all. See `Ui.terminalOptions`.
//!
//! **Which drawing mode the terminal backend uses is phantom's too**, and
//! nothing here names one. `phantom.tui.selectMode` reads the terminal's own
//! graphics capability and the `PHANTOM_TUI` variable, and Chock passes neither,
//! so a terminal that grows one gets it with no change here.
//!
//! ## A second observer, and not a second loop
//!
//! `chock_core.Loop.Observer` already carries everything a person watching a
//! session wants: the model's words as they arrive, what the harness is doing,
//! every event the log takes, and the plan the agent keeps. `src/run.zig`'s
//! `Printer` is one implementation of that seam and this is the second. Nothing
//! in the loop knows either of them exists, and nothing in this file may make it
//! know. A change here that needs a change in `chock_core.Loop` is the wrong
//! change.
//!
//! ## The transcript is the `Printer`'s own bytes
//!
//! This does not print the session a second time. `src/run.zig` gives its
//! `Printer` a buffer instead of standard output, hands this file that
//! `Printer`'s observer, and this file shows the tail of that buffer and writes
//! the whole of it back out when the display comes down. So the words on the
//! screen are, byte for byte, the words `chock run` writes, because there is one
//! writer and not two.
//!
//! ## Every frame goes through the same gate as every other line
//!
//! Phantom writes each frame through `Frames`, a `std.Io.Writer` whose whole
//! body is a call to `tty.writeOut`. So a frame takes the same lock, sits in the
//! same buffer, and is pushed by the same `tty.flushOut` as a table row or a
//! warning. **The buffer is zero length**, so every `writeAll` drains at once
//! and nothing of a frame is left behind when `Loop.run` forks for a tool call.
//!
//! ## Who reads the keyboard, and when, and what that costs Ctrl-C
//!
//! **Phantom never reads the device.** `raw_mode` is false in
//! `phantom.tui.Options`, so `input` defaults to `.fed` and this file is the one
//! reader, because `askForMessage` reads the same descriptor and two readers on
//! one descriptor race for every byte.
//!
//! **Raw mode goes on for exactly two spans, and never at any other moment.**
//! `takeKeys` is the only thing that turns it on and `giveKeys` the only thing
//! that turns it off:
//!
//! 1. **While a message is wanted**, between two turns. See `askForMessage`.
//! 2. **While a question is open**, during a turn. See `awaitAnswer`.
//!
//! The two cannot overlap: `askForMessage` runs between two calls of `Loop.run`
//! and an approval is asked from inside one, on the same thread.
//!
//! **Outside those two spans the echo stays off all the same.** `ISIG` and
//! `ECHO` are independent bits of the terminal's own `c_lflag`, and only the
//! first has to come back for `src/interrupt.zig` to own Ctrl-C. Phantom
//! restores all of them together or none of them, so this file writes the
//! settings itself, in three states rather than two: see `quietOf`, `takeKeys`
//! and `dropKeys`. A turn that ran with the echo on printed every byte the
//! terminal sent at it, and a scroll wheel on the alternate screen sends arrow
//! escape sequences, so a wheel wrote `^[[A` across the transcript.
//!
//! **Raw mode turns `ISIG` off, so Ctrl-C arrives as `0x03` instead of as a
//! signal.** That is what makes the spans as narrow as they are, because a
//! session in raw mode with nothing watching for that byte is a session Ctrl-C
//! cannot stop. Each span answers it:
//!
//! * **At the field**, phantom catches the key before the tree and stops, which
//!   is the right answer for a person who changed their mind before anything
//!   ran.
//! * **At a question**, `awaitAnswer` puts the device back and then raises
//!   `SIGINT` itself, once for each press. So `src/interrupt.zig`'s handler runs
//!   with exactly the meaning it always had, including a second press ending
//!   every running tool call through `chock_core.tools.cancelRunningTool` before
//!   it ends the process. The order is the whole of it: the device first, then
//!   the signal.
//!
//! Outside those two spans `ISIG` is on and Ctrl-C is entirely
//! `src/interrupt.zig`'s. That file writes the escape sequences that put the
//! terminal back, because a second press ends the process where it stands and no
//! deferred teardown runs: see `interrupt.restore_bytes`, and the test below
//! that pins those bytes against what a real phantom session writes. It puts
//! the terminal's own settings back there too, for the same reason and from the
//! same press: see `interrupt.armTerminalSettings`.
//!
//! `query_capabilities` follows raw mode for a related reason: the probe reads
//! the reply itself, past `input`, and a terminal that is not in raw mode
//! answers a read only when the user presses return.
//!
//! **In a window** none of that applies: there is no raw mode, no `ISIG` to turn
//! off, and no shared stream, so Ctrl-C in the terminal it was started from
//! reaches the handler as it always did. What a window has instead is a close
//! button, and `draw` turns that into the same stop: see `interrupt.requestStop`.
//!
//! ## What is not here yet
//!
//! **A resize is not followed.** `start` installs the `SIGWINCH` handler,
//! because `enterRaw` does, but nothing asks `Term.resized` afterwards; a window
//! does report its new size, and `cols` and `rows` here are read once all the
//! same. A person who resizes mid session sees a display that no longer fits
//! until the session ends, and the transcript written out afterwards is
//! unaffected.
//!
//! **The wheel scrolls nothing.** A terminal reports one only with mouse
//! reporting on, and phantom turns its mouse, paste and in band resize modes on
//! inside `enterModes`, which `phantom.tui.Session.init` runs only when its own
//! `raw_mode` is true. Chock holds raw mode itself, for the spans above, so
//! that option is false and those modes are never asked for. The mouse is
//! optional and nothing here is reachable only by it, so the wheel is left
//! doing what a terminal does with it by default: it sends arrow escape
//! sequences. With the echo held off those bytes reach nothing at all, because
//! the settings go on with `TCSAFLUSH`, which drops whatever arrived while
//! nobody was reading.

const std = @import("std");
const phantom = @import("phantom");
const chock_core = @import("chock-core");
const sessions_cmd = @import("sessions.zig");
const session_paths = @import("session.zig");
const chock_proto = @import("chock-proto");
const tty = @import("tty.zig");
const interrupt = @import("interrupt.zig");
const run = @import("run.zig");
const main_cmd = @import("main.zig");
const approval = @import("approval.zig");
const clock_mod = @import("clock.zig");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");

/// What bare `chock` draws on.
pub const Plan = enum {
    /// A window.
    window,
    /// The terminal.
    terminal,
    /// Neither: print the usage page, which is what bare `chock` has always
    /// done.
    usage,
};

/// Turn phantom's own backend choice into what Chock draws.
///
/// **The only thing added to phantom's answer is `terminal_can_draw`**, and it
/// is a second question rather than a second answer. `phantom.app.selectBackend`
/// asks the descriptor whether it is a terminal. This asks whether that terminal
/// can do anything but put characters in order, which is `TERM`, and which
/// phantom never reads. See `tty.terminalCanDraw`, the one place that rule lives.
pub fn decide(backend: phantom.app.Backend, terminal_can_draw: bool) Plan {
    return switch (backend) {
        .gpu => .window,
        .tui => if (terminal_can_draw) .terminal else .usage,
        .none => .usage,
    };
}

/// How long the probe waits for the compositor's keymap, in milliseconds.
///
/// **The keymap is the answer this waits for, and it comes on the wire.** The
/// compositor sends it as soon as the keyboard object is bound, which lattice
/// does at the end of its own start up, so the reply is in the socket before
/// the first poll. Measured against weston on a local socket: a budget of five
/// milliseconds read the answer in twenty runs out of twenty, so this is twenty
/// times what was needed.
///
/// **Almost all of it is margin and not a wait.** A run whose keymap loads pays
/// the whole budget, because silence is not proof: a keymap that had not
/// arrived yet looks exactly like a keymap that loaded. The number is the price
/// of asking a question this stack answers no other way, and one window start
/// pays it once.
const keymap_wait_ms: u32 = 100;

/// The window question, held unasked.
///
/// A struct rather than a call, because asking opens a compositor connection
/// and `windowPossible` decides whether that connection is worth spending.
const Compositor = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,

    /// What one look at a compositor found.
    pub const Answer = enum {
        /// Nothing to open a window on.
        none,
        /// A window that draws, and a keyboard that spells nothing. The
        /// compositor sent a keymap this stack could not read, so a key arrives
        /// with no character on it and a person cannot type one word.
        no_keys,
        /// A window that draws and that takes what a person types.
        ready,
    };

    /// Open one connection and ask it both of its halves: is there a screen, and
    /// can a key become a character on it.
    ///
    /// **`phantom.window.open` and not `phantom.window.available`.** The two ask
    /// the same first question, but `available` opens the connection and closes
    /// it in one act, and the keyboard half needs it to stay up for a moment:
    /// the compositor sends its keymap after the keyboard is bound, so that
    /// answer arrives on the wire and never from the call that opened it.
    ///
    /// **No window is shown.** Nothing is committed to the surface, so the
    /// compositor has nothing to put on a screen. That is what `available` has
    /// always done, and this changes none of it.
    fn look(self: Compositor) Compositor.Answer {
        // The comptime `if` is what keeps every lattice type out of analysis on
        // a target where lattice is a `void`. An early return above would NOT
        // do that: the rest of the body sits at function scope and is analyzed
        // either way. See `phantom.window.open`, which states the same rule and
        // was written for the same fault.
        if (phantom.backend.prism.builds_here) {
            var opened = phantom.window.open(self.gpa, self.io, self.env, .{}) orelse
                return .none;
            defer opened.close();
            return self.keysArrive(&opened.ctx);
        }
        return .none;
    }

    /// Wait for the compositor's keymap and report what became of it.
    ///
    /// **Lattice publishes this on one channel and it is a log line.** The
    /// keymap is untrusted bytes off a socket, so lattice keeps the map it
    /// already has when the new one does not read and writes a warning, and
    /// nothing it returns says which of the two happened. `keymap_watch` reads
    /// that one line: see it for why a wide match is the safe direction.
    ///
    /// The event type is read off phantom's own dispatcher rather than named.
    /// This file does not import lattice and must not: see the top comment.
    fn keysArrive(self: Compositor, ctx: anytype) Compositor.Answer {
        const Ignore = struct {
            const Event = @typeInfo(
                @TypeOf(phantom.window.Session.dispatchEvent),
            ).@"fn".params[1].type.?;
            /// The probe watches for a keymap and acts on no event at all. A
            /// pointer motion or an output notice during the probe is a fact
            /// about a window that is not up yet.
            fn take(_: *anyopaque, _: Event) void {}
        };
        var nothing: u8 = 0;

        keymap_watch = .{ .watching = true };
        defer keymap_watch = .{};

        const started = std.Io.Clock.now(.awake, self.io);
        while (!keymap_watch.failed) {
            const spent = started.durationTo(std.Io.Clock.now(.awake, self.io));
            const spent_ms = @divTrunc(spent.nanoseconds, std.time.ns_per_ms);
            if (spent_ms >= keymap_wait_ms) break;
            // A poll returns as soon as the compositor says anything, so this
            // runs several times over the budget and reads the answer after
            // each one. A connection that breaks under it is no window either.
            ctx.poll(
                @intCast(keymap_wait_ms - @as(u32, @intCast(spent_ms))),
                Ignore.take,
                &nothing,
            ) catch return .none;
        }
        return if (keymap_watch.failed) .no_keys else .ready;
    }
};

/// Whether bare `chock` may try a window.
///
/// **A screen is only a third of it.** `phantom.window.available` reads back a
/// screen and a device, and a device that starts is not a device that draws:
/// `phantom.window.Session.init` goes on to build a pipeline on the device
/// `prism.drivers.createBestDevice` picked, and that is where an Apple M1
/// running cosmic-comp failed with `NotImplemented` after `available` had
/// already said yes. `can_draw` is prism's own rasterizer probe, which draws a
/// rectangle on that same device and reads the pixel back, so the question
/// asked here is the question the session answers. Phantom holds its terminal
/// backend to this rule already and drops pixels to cells when the answer is
/// no: see `phantom.tui.Session.init`.
///
/// **A keyboard nobody can type on is the same shape as a screen nobody can
/// draw on**, and it was found the same way: the window came up on a seated
/// compositor, it drew every frame correctly, and not one key reached it,
/// because the keymap the compositor sent did not read on this machine. A
/// window that draws and swallows every keystroke looks like a working product
/// and is worse than no window at all, so it is refused here with the drawing
/// half. See `Compositor.keysArrive`.
///
/// **The rule both halves keep is one rule: a probe must ask the question the
/// thing actually needs.** A probe that answers a different question than the
/// thing it gates is worse than no probe, because it gates on the answer to
/// something nobody asked.
///
/// **And it heals itself.** The keyboard half reads what lattice reports, turn
/// by turn, so the day lattice reads that keymap the window comes back with no
/// change here and no second decision anywhere.
///
/// **The compositor is asked second, and only then.** A machine that cannot
/// draw opens no connection at all, which is one whole connection this used to
/// spend before spending a second one on the session it was about to fail.
///
/// Exact for a compositor session, which is where both faults were found.
/// Lattice builds its KMS device from the DRM descriptor instead, so on a bare
/// tty the two devices are chosen by different code and the answer is a strong
/// hint rather than the same question.
fn windowPossible(can_draw: bool, compositor: anytype) Compositor.Answer {
    if (!can_draw) return .none;
    return compositor.look();
}

/// What lattice said about the last keymap it was given.
///
/// **A global, because a log function is where the answer lands and a log
/// function takes no state.** `std.log` is the only place lattice reports a
/// keymap it could not read, so this file listens there: see `logMessage`, and
/// `src/main.zig`, which installs it for the whole program.
///
/// Read on one thread. The probe is the whole of the window decision and it
/// runs in `start`, before any session exists and before anything else in
/// Chock has been started.
var keymap_watch: struct {
    /// Whether a probe is listening right now. Off at every other moment, so a
    /// keymap that is replaced mid-session cannot answer a question nobody
    /// asked.
    watching: bool = false,
    /// Whether a keymap failed while the probe listened.
    failed: bool = false,
} = .{};

/// Every `std.log` message in the program, whoever wrote it.
///
/// **Installed for one line**, the one lattice writes when a compositor keymap
/// does not read, and it passes every message on unchanged. See `keymap_watch`
/// for why a log line is the answer at all.
pub fn logMessage(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime saysKeymapFailed(level, format)) {
        if (keymap_watch.watching) keymap_watch.failed = true;
    }
    std.log.defaultLog(level, scope, format, args);
}

/// Whether one log message says a keymap did not load.
///
/// **Comptime**, so this costs a program that logs nothing about keymaps
/// nothing at all: the format string of every message is known where it is
/// written.
///
/// **Wide on purpose.** It matches the word and not the sentence, because the
/// two ways to be wrong are not the same size: a match that should not have
/// fired drops a window to the terminal, which works, and a miss puts up a
/// window a person cannot type in, which is the fault this exists for. A
/// warning about a keymap means the keys are in doubt, whatever it says next.
fn saysKeymapFailed(level: std.log.Level, format: []const u8) bool {
    if (level != .warn and level != .err) return false;
    return std.mem.indexOf(u8, format, "keymap") != null;
}

/// What a person really gets when the window is refused, in words.
///
/// **The two refusals used to say "prints plainly" and that was wrong.** A
/// refused window does not reach the printer: `decide` sends it to the terminal
/// backend, and phantom then draws there in pixels or in cells. The owner hit
/// this on a real desktop, was told Chock would print plainly, and got a full
/// screen interface. Only a stream that is no terminal at all reaches the usage
/// page, which is the second answer below.
///
/// Takes the answer rather than working it out, because `decide` owns that rule
/// and two places deciding it is how the two drift apart.
fn insteadOfAWindow(terminal_can_draw: bool) []const u8 {
    return if (terminal_can_draw) "draws in this terminal" else "prints plainly";
}

/// Whether this machine names a display at all, read from the environment and
/// never from a connection.
///
/// **Free, and that is the whole reason it exists.** A machine that cannot draw
/// is never asked for a compositor connection, by the rule above. So when the
/// window is declined for the drawing half, the environment the desktop set is
/// the only thing left that can say a desktop was there to decline.
///
/// **Used to decide whether to speak, and never to decide whether to draw.** A
/// variable says a compositor was running when the shell started and nothing
/// more, which is too weak to open a window on and strong enough to explain one
/// that did not open.
fn namesADisplay(env: *const std.process.Environ.Map) bool {
    for ([_][]const u8{ "WAYLAND_DISPLAY", "DISPLAY" }) |name| {
        if (env.get(name)) |value| {
            if (value.len != 0) return true;
        }
    }
    return false;
}

/// Bare `chock`: pick a backend, take a message, and run one session with the
/// display up.
///
/// Bare `chock`: bring the interface up, take a message, and run one session in
/// it.
///
/// **The message is typed inside the interface**, in a `phantom.TextField`, and
/// never on a bare line before it. A prompt printed to the terminal and then a
/// display would be a shell that happens to draw afterwards, and a window that
/// printed one would make no sense at all.
///
/// **Standard input that is not a terminal stays non-interactive.** `echo "fix
/// the parser" | chock` and `chock < task.txt` take the message from the stream
/// and run, with no field and nothing to type. See `pipedMessage`.
///
/// **One message and one session, for now.** The field is taken down when the
/// session starts, because from then on the terminal is not read: see
/// `Ui.askForMessage`.
pub fn start(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    // **The command line is read before anything else is decided**, so an
    // option nobody knows is refused by name whatever can or cannot be drawn. A
    // usage page for a mistyped option would say nothing about the option. See
    // `run.readOptions`, which is the one parser both this and `chock run` use.
    const asked = (try run.readOptions(arena, args)) orelse return main_cmd.Exit.usage.code();
    if (asked.help_wanted) return main_cmd.Exit.finished.code();

    // Both halves of "there is a terminal that can draw". The first is the
    // descriptor, which phantom asks about too; the second is `TERM`, which
    // phantom never reads. See `decide`.
    const terminal_can_draw = tty.stdoutIsTty() and tty.terminalCanDraw(env.get("TERM"));
    // **Whether anybody is going to type the first message**, worked out before
    // the display is decided because it decides part of it. Words on the command
    // line are already a message, and standard input that is not a terminal is
    // either a piped message or nothing to run at all. Either way no person
    // types into a field, so a window that cannot read a keyboard costs nothing.
    const message_in_hand = asked.message_words.len != 0 or
        !(std.Io.File.stdin().isTty(io) catch false);
    // The whole of the question on a target the window path does not build for:
    // see `phantom.window.available`, which answers false there.
    const can_draw = phantom.backend.prism.builds_here and phantom.backend.prism.canRasterize(gpa);
    const window = windowPossible(
        can_draw,
        Compositor{ .gpa = gpa, .io = io, .env = env },
    );

    // **A window declined on a desktop says why, because the alternative is a
    // person watching their interface not appear and being told nothing.**
    // Before the drawing half was asked first, a machine like this opened a
    // session, failed inside it, and printed "the display could not start"; see
    // `run.zig`. Asking first is right, and it made the refusal silent, which is
    // this project's own worst failure shape: the answer was correct and it
    // reached nobody.
    //
    // **Only on a machine that named a display.** A session over ssh with no
    // desktop declines the window every time and must stay quiet, because a line
    // about a window nobody asked for is noise on every run.
    if (phantom.backend.prism.builds_here and !can_draw and namesADisplay(env)) {
        tty.print(
            .warn,
            "chock: this machine names a display and no graphics driver on it could draw a test frame, " ++
                "so chock {s} instead of opening a window.\n",
            .{insteadOfAWindow(terminal_can_draw)},
        );
    }
    // **A window refused for its keyboard says why too, and it says it every
    // time.** This one needs no `namesADisplay` guard: the answer came from a
    // compositor connection that opened, so there is a desktop by proof and not
    // by a variable. See `Compositor.keysArrive`.
    // **The window opens either way, and this says what it will not do.** The
    // two shapes differ in how much it costs a person: with a message in hand
    // nothing is typed, so only scrolling and questions are lost. With none,
    // the first message cannot be given at all and the way out is worth naming.
    if (window == .no_keys) {
        if (message_in_hand) {
            tty.print(
                .warn,
                "chock: the keyboard map on this display could not be read, so the window takes no key. " ++
                    "The message is already in hand so the session runs, and scrolling and questions will not work.\n",
                .{},
            );
        } else {
            tty.print(
                .warn,
                "chock: the keyboard map on this display could not be read, so the window takes no key " ++
                    "and the first message cannot be typed into it. Give the message after `--`, " ++
                    "or set PHANTOM_BACKEND=tui to work in this terminal instead.\n",
                .{},
            );
        }
    }
    // **A desktop gets a window. The keyboard decides what is said, never
    // whether it opens.**
    //
    // This gated on the keyboard for one night and the owner overruled it, and
    // the reasoning is worth keeping because it is the stronger argument. A
    // keymap lattice cannot read is an UPSTREAM BUG THAT IS BEING FIXED, and
    // gating on it builds permanent machinery around a temporary fault. Worse,
    // the only way to detect it is to read a dependency's own log line: see
    // `saysKeymapFailed`. A gate resting on prose in somebody else's warning
    // opens silently the day that warning is reworded, which is the failure
    // this project refuses everywhere else.
    //
    // So the detection stays and only its consequence changed. It now decides
    // WHAT IS SAID and not what is drawn, and a missed detection costs a
    // warning rather than a window. That is the cheap direction to be wrong in.
    const window_ready = window != .none;
    const plan = decide(
        phantom.app.selectBackend(env, window_ready, tty.stdoutIsTty()),
        terminal_can_draw,
    );

    // **Read before the display decision is acted on.** A message that is
    // already in hand is a non-interactive run: it needs no field, and it needs
    // no display at all. `echo "fix the parser" | chock > answer.txt` is that
    // case in full, and it has to work whatever can or cannot be drawn.
    //
    // Words on the command line are already a message, so standard input is not
    // read for one. **The words reach here only after `--`, or after an option
    // that came first**, because a first bare word is read as a command name and
    // refused: `main.namesNoCommand` holds that rule, and `chock -- fix the
    // parser` is the form to write in a document.
    const piped = if (asked.message_words.len != 0 or (std.Io.File.stdin().isTty(io) catch false))
        null
    else
        try pipedMessage(arena, io);

    if (plan == .usage) {
        // Nothing can be drawn. A message that is already in hand still runs,
        // and it runs exactly the way `chock run` would: plainly, on standard
        // output, with no display anywhere. The whole command line goes with
        // it, so every option means there what it meant here.
        if (asked.message_words.len != 0) {
            return run.main(arena, gpa, environ, exe_path, args);
        }
        if (piped) |message| {
            const with_message = try std.mem.concat(arena, []const u8, &.{
                args,
                &.{ "--", message },
            });
            return run.main(arena, gpa, environ, exe_path, with_message);
        }
        // Nothing to draw on and nothing to do. Exactly what bare `chock` did
        // before this file existed, including the exit code: `chock | head` and
        // `chock` in a script are the callers this protects, and neither of
        // them wants a full screen application.
        main_cmd.printUsage(.err);
        return main_cmd.Exit.usage.code();
    }

    // **The display is not opened here.** It is opened in `src/run.zig`, after
    // that file has worked out the project, the workspace and the model, so the
    // header band carries them from its very first frame. A band that read
    // `chock` and nothing else while a person typed their first message would
    // be blank for the one thing they look at first.
    const attach: Attach = switch (plan) {
        .terminal => .{ .terminal = .{ .in = std.Io.File.stdin(), .out = std.Io.File.stdout() } },
        .window => .{ .window = .{} },
        .usage => unreachable,
    };
    return run.mainWithInterface(arena, gpa, environ, exe_path, args, attach, piped orelse "");
}

/// One line from standard input, or null when there is none.
///
/// **Read before the display goes up**, and never after: from then on phantom
/// holds the display and this program reads no input at all. See this file's own
/// top comment.
fn pipedMessage(arena: std.mem.Allocator, io: std.Io) !?[]const u8 {
    var buffer: [max_message_bytes]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        // Nothing was typed and the stream ended, which is Ctrl-D on an empty
        // line and `chock < /dev/null`.
        error.EndOfStream => return null,
        error.StreamTooLong => {
            tty.print(
                .err,
                "chock: the message is longer than {d} bytes.\n",
                .{max_message_bytes},
            );
            return null;
        },
        error.ReadFailed => {
            tty.print(.err, "chock: standard input could not be read.\n", .{});
            return null;
        },
    };

    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;
    // Copied out of the reader's own buffer, which is a stack local here.
    return try arena.dupe(u8, trimmed);
}

/// The longest message this asks for. One line typed by a person, so the bound
/// is generous rather than tuned. A longer message goes to `chock run`, which
/// reads the whole of standard input.
const max_message_bytes = 4096;

/// How the rows of the screen are shared out between the regions.
pub const Split = struct {
    /// Rows the header band gets.
    header: u16,
    /// Rows the transcript gets: everything the other regions do not take.
    transcript: u16,
    /// Rows the approval region gets. Zero when there is no question, which is
    /// what makes its arrival a signal.
    approval: u16,
    /// Rows the input band gets.
    input: u16,
};

/// The header and the input are one row each. A very short screen keeps them
/// and the transcript gives up rows first, because the transcript is the one
/// thing that can be scrolled back to.
const band_rows: u16 = 1;

/// Share the rows out between the regions.
///
/// **The header and the input never lose their row.** A screen with two rows is
/// those two bands and no transcript; a screen with one is the input alone,
/// because a person who cannot type cannot leave. Only at zero is there nothing.
///
/// **The approval takes its rows from the transcript and never from a band.**
/// On a very short screen the header and the approval keep their rows, and the
/// transcript gives up rows first, because it is the one thing that can be
/// scrolled back to. So `wanted` is met in full while there is anything left to
/// take, and the transcript is what goes to zero.
pub fn split(rows: u16, wanted: u16) Split {
    if (rows == 0) return .{ .header = 0, .transcript = 0, .approval = 0, .input = 0 };
    if (rows == 1) return .{ .header = 0, .transcript = 0, .approval = 0, .input = band_rows };
    const room = rows - 2 * band_rows;
    const asked = @min(wanted, room);
    return .{
        .header = band_rows,
        .transcript = room - asked,
        .approval = asked,
        .input = band_rows,
    };
}

/// The rows of one region, and never one row more than the region was given.
///
/// **A row a region has no room for must not be drawn at all.** A band is a
/// surface exactly `rows` measured line boxes tall, and the band under it is
/// painted after it: see `Ui.view`, which builds them in order, and `Ui.band`,
/// which gives each one its own surface. So a row placed past the end of a band
/// is not clipped by that band. It is covered by the surface of the next one,
/// and what a person sees is a row of glyphs cut through by a straight edge.
///
/// **Every region that shares its rows out needs this.** Three of them work out
/// what each part gets by subtraction, and a subtraction that saturates at zero
/// gives back rows that were never there: a completion list as long as the
/// transcript, a pane on a screen with one row, an approval region too short
/// for the two rows it always keeps. Each of those really did draw past its
/// band. See `Ui.transcriptRows`, `Ui.paneRows` and `Ui.approvalRegion`.
const Rows = struct {
    into: std.ArrayList(phantom.Widget) = .empty,
    /// How many more rows there is room for.
    left: u16,

    /// Take one more row, or nothing when the region is full.
    fn add(self: *Rows, arena: std.mem.Allocator, one: phantom.Widget) void {
        if (self.left == 0) return;
        self.left -= 1;
        // A row that could not be kept is a row that is not drawn, which is the
        // same outcome as a row there was no space for.
        self.into.append(arena, one) catch {};
    }

    fn items(self: Rows) []const phantom.Widget {
        return self.into.items;
    }
};

/// What one byte of a raw line draws as, and how much of the line it takes.
///
/// **Every control character becomes a space.** The cell writer sends a cell's
/// codepoint straight at the terminal, so an escape byte in a tool's own output
/// would leave this file writing an escape sequence it never composed, at a
/// place on the screen it did not choose. A tab is in the same class: nothing
/// here knows where a tab stop is.
///
/// **Every byte that is not valid UTF-8 becomes a question mark.** Phantom
/// measures a line by decoding it and gives a line it cannot decode no size at
/// all, so one bad byte in a tool's output would make the whole line vanish
/// rather than show wrongly.
const Drawn = struct {
    /// The codepoint that really goes on the screen.
    point: u21,
    /// How many bytes of the raw line it stands for.
    length: usize,
    /// Whether those bytes can be copied out as they are. False for a byte that
    /// was replaced, which is written as one byte of its own.
    whole: bool,
};

/// What the byte at `at` draws as. **One decoder for the whole file**, so what
/// a row measures and what a row shows can never disagree.
fn drawnAt(raw: []const u8, at: usize) Drawn {
    const size = std.unicode.utf8ByteSequenceLength(raw[at]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (at + size > raw.len) return .{ .point = '?', .length = 1, .whole = false };
    const point = std.unicode.utf8Decode(raw[at..][0..size]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (point < 0x20 or point == 0x7f) return .{ .point = ' ', .length = size, .whole = false };
    return .{ .point = point, .length = size, .whole = true };
}

/// `raw`, with every byte in it made safe to draw and nothing taken off.
///
/// **Phantom's own layout refuses a run it cannot decode**, and a control byte
/// would reach the terminal as a sequence this file never composed, so this
/// runs before anything measures or breaks the line. See `drawnAt`.
fn safeText(
    arena: std.mem.Allocator,
    raw: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < raw.len) {
        const one = drawnAt(raw, index);
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
    }
    return out.items;
}

/// One line of the transcript, as it can safely be drawn, cut to `room`.
///
/// **Measured against the face the display draws in, and never divided by a
/// column.** A character grid has a column and a real font does not, so every
/// glyph is stepped by the advance it truly has: see `Measure.advanceOf`. A row
/// this returns measures inside `room` whatever letters are in it, and a row of
/// narrow letters keeps every one of them.
///
/// **Cut and not broken.** A band that may not grow shows what fits and stops:
/// see `wrapText`, which is what the transcript uses instead.
fn visibleLine(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    var used: f32 = 0;

    while (index < raw.len) {
        const one = drawnAt(raw, index);
        // A glyph that would cross the right edge is left off rather than half
        // drawn, and the loop stops there.
        const advance = room.measure.advanceOf(one.point);
        if (used + advance > room.width) break;
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
        used += advance;
    }

    return out.items;
}

/// A codepoint Chock writes that phantom can draw as a mark of its own.
///
/// **The bundled faces have none of these.** Measured against the theme's own
/// body face at size 16: `\u{2713}`, `\u{2717}`, `\u{2502}` and `\u{2500}` all
/// advance 11.168, which is the advance of glyph 0, so each of them rasterised
/// as a replacement box. `\u{b7}` advances 3.584 and `\u{2026}` 13.12, which is
/// how those two are known to be real glyphs and are left alone.
///
/// **The pixel backend no longer needs this to draw a shape, and that is not
/// the reason to keep it.** `phantom/backend/prism.zig` now stands a built-in
/// mark in for any glyph the face is missing, inside a run of text, so every
/// codepoint here rasterises as a vector with or without the line below it.
/// What a line here decides is what a cell backend paints, what size and place
/// the mark takes on the row, and what name a screen reader hears, and none of
/// those three is a per-glyph fallback's to decide. See `markBox`, which is
/// where the rail is made full height, which a fallback would draw square.
///
/// **Two of these change what a character terminal paints, on purpose.**
/// `phantom.icon.cellMarkFor` gives most of these marks back the very codepoint
/// that is written here, so a cell backend paints what it painted before. The
/// two chevrons are the exception: phantom spells them with the large
/// triangles, so `\u{25b8}` reaches a terminal as `\u{25b6}` and `\u{25be}` as
/// `\u{25bc}`. Phantom states that the small and the large triangle are two
/// spellings of one mark and not two marks, so this is a change of spelling and
/// never of meaning. See `markBox`, and the capture tests that pin the new
/// characters.
///
/// **The third of the late three costs a terminal nothing.**
/// `cellMarkFor(.ellipsis)` is `\u{22ef}`, the codepoint written here, so the
/// running call mark reaches a cell backend exactly as it did before.
const Mark = struct {
    id: phantom.icon.Id,
    /// What a screen reader announces for this mark, or null for a mark that
    /// says nothing a reader needs.
    ///
    /// **Not the character a terminal paints.** That is
    /// `phantom.icon.cellMarkFor`, and it is chosen by phantom from the id.
    /// This is a name for somebody who cannot see the mark at all, so the two
    /// are different fields for different readers and neither stands in for
    /// the other.
    label: ?[]const u8,
};

fn markFor(point: u21) ?Mark {
    return switch (point) {
        '\u{2713}' => .{ .id = .check, .label = "ok" },
        '\u{2717}' => .{ .id = .cross, .label = "not ok" },
        // **A rule is structure and carries no name.** The rail is on every row
        // Chock speaks on, so a name there is read out once per row for
        // nothing, and the horizontal rule stands beside the words that say
        // what it means.
        '\u{2502}' => .{ .id = .rule_vertical, .label = null },
        '\u{2500}' => .{ .id = .rule_horizontal, .label = null },
        // **A chevron carries no name because it means a different thing in
        // each of its three places.** It opens a fold, it points at the chosen
        // row of a list, and it stands between the names of a spawn chain. One
        // name would be right in one of the three and wrong in the other two,
        // and every one of them has the words that say what it means beside it.
        '\u{25b8}' => .{ .id = .chevron_right, .label = null },
        '\u{25be}' => .{ .id = .chevron_down, .label = null },
        // **The third of the three glyphs a tool call row can carry**, beside
        // `\u{2713}` and `\u{2717}`, so it is named the way those two are.
        '\u{22ef}' => .{ .id = .ellipsis, .label = "running" },
        else => null,
    };
}

/// The most room the transcript uses, however wide the display is, stated in
/// characters.
///
/// **A very wide display needs a measure**: the transcript stops growing at a
/// readable measure, and a line never runs to 200 columns.
///
/// **The measure is the design width**, which is 80 columns, where everything
/// must work. Taking that as the measure means a wide terminal shows the
/// transcript the design draws and leaves the rest as margin, and a terminal at
/// the design width or narrower still uses every column it has.
///
/// **A count of characters and not a width**, because a design measure is
/// stated in characters in every book on typography. `Measure.step` is what
/// turns it into a width for the face in use, and it is the only thing in this
/// file that does. Nothing is ever fitted against it.
pub const readable_columns: u16 = 80;

/// Break `raw` into rows that each fit in `room`.
///
/// **A row that ran off the edge was a row a person could not finish reading.**
/// Cutting is right for a band that may not grow, which is the header, the
/// approval region and a pane. It is wrong for the transcript, where the words
/// are the session and the rest of a sentence is not a decoration.
///
/// **Phantom decides where the break falls and this file does not.** Where a
/// line breaks has to agree with how it is measured, and phantom's own
/// `layoutParagraph` asks the same question per glyph that its `layoutLine`
/// asks when it draws one. A second break rule here would be a second answer
/// that can drift from the one on the screen: at a space where there is one,
/// between characters in a word too long for the measure, and always at a line
/// feed.
///
/// **The bytes go through `safeText` first**, so a control byte is a space and
/// a byte that is not UTF-8 is a question mark before anything measures them.
/// Phantom gives a run it cannot decode no layout at all, which would lose a
/// whole row of a tool's output.
///
/// **Each row is read back from the glyphs that were laid out**, and not sliced
/// out of the source by a count this file keeps. The break returns positions in
/// phantom's own terms, and re-encoding what it laid out is what makes the rows
/// exactly the rows that were measured.
///
/// **Always at least one row**, so a line the agent left empty stays an empty
/// row rather than disappearing.
fn wrapText(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    // A measure of nothing has no rows to break into, and the whole line is one
    // row that the region it is drawn in gives no room to. This is also what
    // keeps a display that has not measured itself yet away from the face:
    // see `grid_measure`.
    if (!(room.width > 0)) {
        try out.append(arena, "");
        return out.items;
    }

    const safe = try safeText(arena, raw);
    const broken = phantom.text.layout.layoutParagraph(
        arena,
        room.measure.font,
        safe,
        room.measure.size,
        room.measure.logicalMetrics(),
        room.width,
    ) catch {
        // A face that cannot lay the row out leaves the row whole rather than
        // dropping it. The words are the session.
        try out.append(arena, safe);
        return out.items;
    };
    // The arena owns everything the paragraph allocated, so there is nothing
    // to give back and nothing that can outlive the frame it was built in.

    for (broken.lines) |line| {
        var words: std.ArrayList(u8) = .empty;
        for (line.glyphs) |one| {
            var bytes: [4]u8 = undefined;
            const length = std.unicode.utf8Encode(one.cp, &bytes) catch continue;
            try words.appendSlice(arena, bytes[0..length]);
        }
        try out.append(arena, words.items);
    }
    // A paragraph always has a line, so this is only the guard that keeps the
    // promise above true whatever phantom returns.
    if (out.items.len == 0) try out.append(arena, "");
    return out.items;
}

/// The first and the last codepoint of the range a face is measured over.
///
/// **The printable ASCII range, and not a chosen letter.** A face whose widest
/// or narrowest glyph is not the one somebody guessed still measures correctly.
const first_printable: u21 = ' ';
const last_printable: u21 = '~';
const printable_count = last_printable - first_printable + 1;

/// What one row of text really measures, in the logical pixels phantom lays
/// out in.
///
/// **This is the answer to the one number this file used to invent.**
/// `phantom.tui.term.logical_cell_h` is a nominal 16, and its own doc comment
/// says what it is for: it is the divisor that turns a terminal's REPORTED cell
/// height into a device pixel ratio. It is not a line box and it is not a font
/// size. A band built as `rows * 16` that holds text drawn at size 16 cuts
/// every glyph whose ascent and descent together are taller than the size,
/// which is every font: the two built in faces both measure 1.2 em, so a row at
/// size 16 wants 19.2 and gets 16.
///
/// **A row is measured and never divided into columns.** A character grid has a
/// column and a real font does not, so `advanceOf` gives one glyph the advance
/// it truly has and `Room` counts a run of them. The one number stated in
/// characters is the design measure `readable_columns`, and `step` is the only
/// thing that turns it into a width.
///
/// **Measured against the real ink, and that has been checked.** The line box
/// is the ascent less the descent, which is what phantom's own text layout uses
/// for the run it draws. Every printable glyph of the theme's own face was
/// rasterised at 24, 33 and 48 pixels and measured against that box: the ink
/// overshoots it by at most 0.2 of a pixel, which is where the rasteriser
/// rounds a coverage bitmap out to whole pixels. So the box bounds the ink and
/// a band of `rows` boxes holds `rows` rows of glyphs.
pub const Measure = struct {
    /// How text measures. `.mono` is the character grid, `.proportional` is a
    /// real font drawn at a real size.
    metrics: phantom.text.mono.TextMetrics,
    /// How many physical pixels one logical pixel covers. The mono metrics are
    /// in PHYSICAL pixels, because that is the space the cell grid uses, and
    /// every size this file gives a widget is LOGICAL, so the two are divided
    /// apart here and nowhere else.
    dpr: f32,
    /// The face the row is drawn in, and the size it is drawn at. Read from the
    /// theme, so this file names no font and no size of its own.
    font: *phantom.text.Font,
    size: f32,
    /// The answers worked out once for the frame, or null while they have not
    /// been.
    ///
    /// **Because asking a real face is not free.** `advanceOf` asks the font
    /// for one codepoint, which is a lookup in the character map and then in
    /// the horizontal metrics, and a screen of text asks for every glyph of
    /// every row. The printable range is measured once in `of` and read from
    /// there afterwards. Null is what a value built by hand in a test holds,
    /// and every answer is then worked out as it is asked for, which costs more
    /// and says the same.
    known: ?Known = null,

    /// What a frame measures once and reads many times.
    const Known = struct {
        /// The height of one row. See `height`.
        line: f32,
        /// The width of one typical character. See `step`.
        typical: f32,
        /// The advance of every printable ASCII codepoint, in order from
        /// `first_printable`.
        ascii: [printable_count]f32,
    };

    /// The numbers, taken from what phantom itself is holding.
    ///
    /// **The owner and not the element tree.** `BuildContext.element` is null
    /// during the first top down mount, so anything read through `inheritedOf`
    /// is unavailable on exactly the frame that decides how much room there is.
    /// `owner.text_metrics` and `owner.activeView()` are the same values the
    /// installed `MediaQuery` reports, and both are there before the tree is.
    pub fn of(ctx: *phantom.BuildContext) Measure {
        const theme = phantom.theme.defaultTheme(ctx.owner);
        const view = ctx.owner.activeView();
        return (Measure{
            .metrics = ctx.owner.text_metrics,
            .dpr = if (view) |one| one.metrics.dpr else 1,
            .font = theme.body_font,
            .size = theme.text_size,
        }).measured();
    }

    /// The same measurement with every answer already worked out. See `known`.
    ///
    /// **Every answer comes from the same code as before.** Each one is asked
    /// for once here, through the very path a caller with no cache takes, so a
    /// cached answer and a fresh one can differ only if this loop indexes
    /// wrongly. A test pins exactly that.
    /// **Every answer is worked out into a value of its own first, and the
    /// field is written once at the end.** Zig gives a struct literal the
    /// address it is being stored into, and for an optional that means the
    /// "there is a value" flag is set before the fields are filled. Writing
    /// `known` directly would therefore make `height` read the very field it
    /// was being called to produce, which is memory nobody has written: the
    /// display then divided its viewport by a number out of the air, saturated
    /// its row count, and drew every band of the screen on the top line.
    pub fn measured(self: Measure) Measure {
        var made = self;
        made.known = null;
        var found: Known = undefined;
        var total: f32 = 0;
        for (&found.ascii, 0..) |*one, at| {
            one.* = made.advanceOf(first_printable + @as(u21, @intCast(at)));
            total += one.*;
        }
        const mean = total / printable_count;
        found.line = made.height();
        // A face that advances nowhere would turn a design measure into an
        // unbounded width. See `height`.
        found.typical = if (mean > 0) mean else made.size;
        made.known = found;
        return made;
    }

    /// A ratio that can never be zero or negative, whatever a backend reports.
    /// A zero here would divide a viewport into an unbounded number of rows.
    fn ratio(self: Measure) f32 {
        return if (self.dpr > 0) self.dpr else 1;
    }

    /// The height of one row.
    ///
    /// **The cell grid states it outright.** `Mono.line` is the terminal's own
    /// reported cell height, so a row is a cell and there is nothing to derive.
    ///
    /// **A pixel run measures the font**, which is the same sum phantom's own
    /// text layout makes for the run it lays out: the ascent less the descent,
    /// scaled from font units to the size asked for. So a row is exactly as
    /// tall as the glyphs that can appear on it.
    pub fn height(self: Measure) f32 {
        if (self.known) |one| return one.line;
        return switch (self.metrics) {
            .mono => |cell| cell.line / self.ratio(),
            .proportional => blk: {
                const per_em: f32 = @floatFromInt(self.font.unitsPerEm());
                // A face with no em cannot be measured. The size is the closest
                // honest answer and it is still finite, which a divide by zero
                // is not.
                if (per_em <= 0) break :blk self.size;
                const up: f32 = @floatFromInt(self.font.ascent());
                const down: f32 = @floatFromInt(self.font.descent());
                break :blk (up - down) * self.size / per_em;
            },
        };
    }

    /// The same measurement in the logical pixels a widget is given, which is
    /// the space every width in this file is in.
    ///
    /// **The cell grid is reported in physical pixels** because that is the
    /// space a cell occupies, and a real face is asked at a logical size, so
    /// only the one has to be divided back. This is what phantom's own
    /// `layoutParagraph` is handed, so the width it breaks against and the
    /// width this file asked for are the same number.
    pub fn logicalMetrics(self: Measure) phantom.text.mono.TextMetrics {
        return switch (self.metrics) {
            .mono => |cell| .{ .mono = .{
                .advance = cell.advance / self.ratio(),
                .line = cell.line / self.ratio(),
                .ascent = cell.ascent / self.ratio(),
            } },
            .proportional => .proportional,
        };
    }

    /// How far one codepoint moves the pen.
    ///
    /// **The cell grid multiplies its cell by the column count**, which is one
    /// for ordinary text and two for a Japanese or a fullwidth glyph. A real
    /// face is asked instead, because that is the only thing that knows.
    ///
    /// **The same sum phantom makes, and it has to be.** Phantom's own layout
    /// asks exactly this per glyph, and it is the thing that decides where a
    /// row breaks. It cannot be called from here: it wants an allocator and a
    /// laid out run, and `Room` answers with neither. So the two agree by being
    /// the same two lines, and a test measures one against the other.
    ///
    /// **A control character and a byte that is not UTF-8 never reach here as
    /// themselves.** `drawnAt` has already turned the first into a space and
    /// the second into a question mark, so what is measured is what is drawn.
    pub fn advanceOf(self: Measure, point: u21) f32 {
        if (point >= first_printable and point <= last_printable) {
            if (self.known) |one| return one.ascii[point - first_printable];
        }
        return switch (self.metrics) {
            .mono => |cell| blk: {
                const columns: f32 = @floatFromInt(phantom.text.mono.wcwidth(point));
                break :blk cell.advance * columns / self.ratio();
            },
            .proportional => self.font.advance(point, self.size),
        };
    }

    /// How wide `text` draws, measured the way `visibleLine` cuts it.
    pub fn widthOf(self: Measure, text: []const u8) f32 {
        var index: usize = 0;
        var used: f32 = 0;
        while (index < text.len) {
            const one = drawnAt(text, index);
            used += self.advanceOf(one.point);
            index += one.length;
        }
        return used;
    }

    /// The width one typical character takes.
    ///
    /// **For turning a measure stated in characters into a width, and for
    /// nothing else.** `readable_columns` and `narrow_columns` are both counts
    /// of characters, because that is how a design measure and a breakpoint are
    /// written. Nothing is ever fitted against this: a run is fitted by
    /// `advanceOf`, one glyph at a time.
    ///
    /// **The mean over the printable range**, which is the honest answer for a
    /// face where every letter is a different width. The cell grid gives its
    /// own cell, because there every letter is the same width already.
    pub fn step(self: Measure) f32 {
        if (self.known) |one| return one.typical;
        var total: f32 = 0;
        var point: u21 = first_printable;
        while (point <= last_printable) : (point += 1) total += self.advanceOf(point);
        const mean = total / printable_count;
        return if (mean > 0) mean else self.size;
    }

    /// How many whole rows of text a viewport of this logical height holds.
    pub fn rowsIn(self: Measure, logical_height: f32) u16 {
        return countIn(logical_height, self.height());
    }
};

/// A character grid whose cell is one unit wide and one unit tall.
///
/// **What the display has before it has measured anything**, and what a caller
/// that states a width in columns asks for. Every printable ASCII glyph is one
/// unit here and a Japanese glyph is two, so a width in these units is a column
/// count. See `Room.grid`.
const grid_measure: Measure = .{
    .metrics = .{ .mono = .{ .advance = 1, .line = 1, .ascent = 0.8 } },
    .dpr = 1,
    // **Never read, and the one caller that would read it cannot be reached
    // with this.** Every `.mono` answer above comes from the cell and needs no
    // face. `wrapText` is the only thing here that hands a face to phantom, and
    // it returns before it does that when the room has no width, which a
    // display that has not measured itself yet always has.
    .font = undefined,
    .size = 1,
};

/// How much room a run of text has, and the face to measure it with.
///
/// **A width and not a column count.** The cell is the unit of layout, which a
/// character grid answers exactly and a real font does not: a proportional face
/// has no column, so a run has to be measured against the advances it really
/// has rather than divided by a made up one.
pub const Room = struct {
    /// The face the run is drawn in. See `Measure`.
    measure: Measure,
    /// How much space it has across, in the logical pixels phantom lays out in.
    width: f32,

    /// A room measured in character cells.
    ///
    /// **It measures and it cuts, and it cannot wrap.** A grid needs no face
    /// and carries none, and `wrapText` hands the face to phantom. See
    /// `grid_measure`.
    pub fn grid(columns: f32) Room {
        return .{ .measure = grid_measure, .width = columns };
    }

    /// The room left once `text` at the front of the row has taken its own
    /// width. Never below zero.
    pub fn less(self: Room, text: []const u8) Room {
        const taken = self.measure.widthOf(text);
        return .{
            .measure = self.measure,
            .width = if (self.width > taken) self.width - taken else 0,
        };
    }

    /// The same room, and never wider than `width`.
    pub fn upTo(self: Room, width: f32) Room {
        return .{ .measure = self.measure, .width = @min(self.width, width) };
    }

    /// Whether `text` fits here whole.
    pub fn holds(self: Room, text: []const u8) bool {
        return self.measure.widthOf(text) <= self.width;
    }

    /// Whether this is one of the narrow displays `narrow_columns` names.
    pub fn isNarrow(self: Room) bool {
        return self.width < @as(f32, narrow_columns) * self.measure.step();
    }
};

/// How many whole `step`s fit in `room`, as a row count.
///
/// **Nothing negative and nothing unbounded.** A viewport is reported by a
/// backend and a step is measured from a font, so neither is this file's to
/// trust: a viewport of zero is a display with no room, and a step of zero
/// would be an unbounded count rather than a large one.
fn countIn(room: f32, step: f32) u16 {
    if (!(room > 0) or !(step > 0)) return 0;
    const whole = @floor(room / step);
    if (whole >= @as(f32, std.math.maxInt(u16))) return std.math.maxInt(u16);
    return @intFromFloat(whole);
}

/// Where a frame's bytes go: through `src/tty.zig`, the same way every other
/// line of this program goes.
///
/// **A zero length buffer.** `std.Io.Writer` drains on every `writeAll` when it
/// has nowhere to hold bytes, so a frame is at `tty`'s own standard output
/// buffer the moment phantom writes it. That matters because
/// `chock_core.Loop.run` forks for every tool call, and a buffer that is empty
/// at every fork is one less thing to reason about.
///
/// **`tty`'s buffer is a second one, and `flush` is what empties it.** Standard
/// output holds eight kilobytes, so bytes that reached it have still not reached
/// the terminal.
const Frames = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },

    const vtable: std.Io.Writer.VTable = .{ .drain = drain, .flush = flush };

    /// A failed write is dropped, the same way `Printer` drops one: a terminal
    /// that went away must not end a session that is doing real work.
    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        _ = w;
        var written: usize = 0;
        // The contract in `std.Io.Writer.VTable.drain`: each slice of `data` in
        // order, and the last slice repeated `splat` times. There is nothing
        // buffered to send first, because the buffer is empty by construction.
        for (data[0 .. data.len - 1]) |slice| {
            _ = tty.writeOut(slice);
            written += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            _ = tty.writeOut(last);
            written += last.len;
        }
        return written;
    }

    /// Push what `src/tty.zig` holds out to the descriptor.
    ///
    /// **The capability probe is what needs this.**
    /// `phantom.tui.Session.init` writes its queries through this writer,
    /// flushes it, and then reads the terminal's reply against a budget of
    /// about three seconds. Standard output has a buffer of its own and this
    /// runs before any frame is painted, so without this the queries sat in
    /// that buffer for the whole budget, no reply could arrive, and every
    /// capability came back false: no pixels, no synchronised output and no in
    /// band resize, on a terminal that has all three.
    ///
    /// A frame needs it for a smaller reason: bytes waiting in a buffer are a
    /// frame nobody has seen.
    ///
    /// **Nothing of this writer's own is drained here.** The buffer is zero
    /// length by construction, so there is never anything in it to send.
    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = w;
        tty.flushOut();
    }
};

/// Where a line written to standard error goes while a display is up.
///
/// ## The fault this repairs
///
/// `terminalOptions` sets `.stderr = .leave`, so standard error points at the
/// real terminal for the whole session. A warning therefore landed **on** the
/// alternate screen, `tty.print` counted it as a scroll, and the next frame
/// repainted every cell over the top of it. The line was not hidden behind the
/// display. It was erased.
///
/// **Nothing is silenced by moving it.** Every line still reaches a person, as
/// a row of the transcript and in the bytes `Ui.stop` writes back to the real
/// screen. What changes is where a person reads it.
///
/// **Chock's own voice, at column 0, under the rail.** A diagnostic is the
/// harness talking to the person and never the model talking, which is the same
/// rule a message a person typed already follows. See `Voice`.
///
/// ## Two things this must never do
///
/// **It must not draw.** `tty.print` holds `src/tty.zig`'s one lock across the
/// whole of a message, and every frame reaches the terminal through
/// `tty.writeOut`, which takes that same lock. A frame built from inside this
/// writer would therefore wait for a lock its own caller holds. So a line is
/// folded into rows here and the next frame shows it, and every event, piece
/// and notice draws one.
///
/// **It must not keep an escape sequence.** A row of the transcript is drawn
/// into cells, and `visibleLine` turns an escape byte into a space and leaves
/// the rest of the sequence as text a person did not write. The painter for
/// standard error is decided from the real terminal and stays on, so `print`
/// really does wrap a warning in SGR bytes. See `keep`.
///
/// ## One writer for one display, on one thread
///
/// `Ui` is driven by one thread by construction: the loop calls the observer,
/// and the observer is what folds a row. A diagnostic from a second thread
/// would reach `say` beside that fold, so the display is for bare `chock`,
/// which is one session in one process. `chock daemon`, which does have
/// threads, brings up no display at all.
const Diagnostics = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },
    /// The display these rows belong to, or null when this writer is not
    /// installed. `Ui.start` fills it and `finish` clears it.
    ui: ?*Ui = null,
    /// The writer standard error had before this took it. Put back by `finish`.
    was: ?*std.Io.Writer = null,
    /// The bytes of a line whose newline has not arrived. **A `tty.print` is
    /// three writes**, the escape, the text and the reset, so a line reaches
    /// this in pieces even when the caller composed the whole of it in one
    /// call.
    held: std.ArrayList(u8) = .empty,
    /// How far into an escape sequence the last byte left this. See `keep`.
    escape: Escape = .none,

    /// Where a sequence of escape bytes has reached.
    ///
    /// **Three states and not a flag**, because the byte after `ESC` decides
    /// how long the sequence is. `ESC [` opens a control sequence that runs to
    /// its own final byte, and every other byte after `ESC` is a sequence of
    /// two bytes that has already ended. A flag cleared on the first byte in
    /// the final range would end `\x1b[33m` at the `[`, which is in that range,
    /// and put `33m` in the row.
    const Escape = enum { none, after_esc, in_csi };

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Diagnostics = @fieldParentPtr("writer", w);
        // The contract in `std.Io.Writer.VTable.drain`: each slice of `data` in
        // order, and the last slice repeated `splat` times. There is nothing
        // buffered to send first, because the buffer is empty by construction.
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            self.keep(slice);
            written += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            self.keep(last);
            written += last.len;
        }
        return written;
    }

    /// Take some bytes of a diagnostic, and close every row a newline in them
    /// ends.
    ///
    /// **An escape sequence is dropped rather than kept**, for the reason this
    /// struct's own comment gives. Only the sequences `tty.Painter` writes can
    /// arrive here from Chock's own lines, and those are all `ESC [` sequences;
    /// a stray `ESC` in text a diagnostic quoted costs the one byte after it
    /// and nothing more.
    fn keep(self: *Diagnostics, bytes: []const u8) void {
        const one = self.ui orelse return;
        for (bytes) |byte| {
            switch (self.escape) {
                .none => {},
                .after_esc => {
                    self.escape = if (byte == '[') .in_csi else .none;
                    continue;
                },
                .in_csi => {
                    // A control sequence ends at the first byte in its own
                    // final range. Everything before that is a parameter or an
                    // intermediate byte.
                    if (byte >= 0x40 and byte <= 0x7e) self.escape = .none;
                    continue;
                },
            }
            if (byte == 0x1b) {
                self.escape = .after_esc;
                continue;
            }
            if (byte == '\n') {
                self.emit(one);
                continue;
            }
            self.held.append(one.gpa, byte) catch {};
        }
    }

    /// Put the line that has been assembled on the display, and in the bytes
    /// the display writes back to the real screen.
    ///
    /// **Both, because the two are read at different times.** The rows are what
    /// a person sees while the session runs, and `Ui.transcript` is what is
    /// left in the terminal's scrollback afterwards. A warning in only the
    /// first would be a warning that vanished when the display came down, which
    /// is a quieter shape of the very fault this exists to fix.
    ///
    /// **`endRow` and not `endLine`**, so a blank line inside a refusal is a
    /// blank row. It is Chock's own content, exactly as a blank line the agent
    /// wrote is the agent's.
    fn emit(self: *Diagnostics, one: *Ui) void {
        one.say(.chock, self.held.items);
        one.endRow();
        one.transcript.appendSlice(one.gpa, self.held.items) catch {};
        one.transcript.append(one.gpa, '\n') catch {};
        self.held.clearRetainingCapacity();
    }

    /// Close whatever was left open, and give standard error back.
    ///
    /// **A line with no newline is still a line a person has to read.** Nothing
    /// promises a diagnostic ends in one, and the last thing written before a
    /// display comes down is exactly where a missing newline would be.
    ///
    /// Safe to call when nothing was ever installed, which is what makes it
    /// safe on a `Ui` whose `start` returned an error.
    fn finish(self: *Diagnostics, io: std.Io) void {
        const one = self.ui orelse return;
        if (self.held.items.len != 0) self.emit(one);
        self.ui = null;
        _ = tty.useErrStream(io, self.was);
        self.was = null;
    }
};

/// What `start` is told about the thing it is drawing on. One member for each
/// backend Chock can drive, and `decide` is what picks between them.
pub const Attach = union(enum) {
    terminal: Terminal,
    window: Window,

    pub const Terminal = struct {
        /// The terminal device. **Phantom never reads it**: `input` is `.fed`
        /// and nothing feeds it, so the only readers are `Ui.askForMessage`,
        /// while a message is being typed, and `Ui.awaitAnswer`, while a
        /// question is open. Never both at once: see this file's own top
        /// comment.
        in: std.Io.File,
        /// Where phantom asks for the window size. Every real caller passes
        /// standard output. **The frames do not go here**: they go through
        /// `Frames`, whatever this says.
        out: std.Io.File,
        /// The grid geometry, instead of asking the device. Null is every real
        /// caller. A test states one, which is what lets the whole path run
        /// with no terminal anywhere.
        size: ?phantom.tui.term.Size = null,
    };

    pub const Window = struct {
        width: u32 = 960,
        height: u32 = 640,
    };
};

/// What the header band says about this session.
///
/// **Every one of these is a fact only `src/run.zig` holds**, so it hands them
/// over once, at the same moment it connects the observer. They are borrowed:
/// each lives in that file's own arena for the whole run.
///
/// **The layers are the one part a person is there to see.** The rest of the
/// header is context, and this is whether the thing is actually contained. So
/// the layers keep their room and a context fact is dropped when the row is too
/// narrow for both. See `headerPieces`.
pub const Facts = struct {
    /// The project directory, as a person would name it.
    project: []const u8 = "",
    /// How the workspace is made: a git worktree, or an overlay.
    workspace: []const u8 = "",
    /// The model as a person names it.
    model: []const u8 = "",
    /// The provider instance behind that model.
    provider: []const u8 = "",
    /// Every sandbox layer, in the order the header names them. Empty until
    /// `src/run.zig` hands them over, and an empty set draws no layers rather
    /// than six that claim nothing.
    layers: []const Layer = &.{},
};

/// One sandbox layer, as the header says it.
///
/// **Nothing here is worked out from the platform.** `src/run.zig` builds these
/// from what the sandbox driver declares it gives and from this session's own
/// config: see `run.sandboxLayers`, which is where that reasoning lives and
/// where a test can reach it.
pub const Layer = struct {
    /// What the layer is called: `net`, `fs`, `pid`, `ipc`, `seccomp`,
    /// `landlock`.
    name: []const u8,
    /// One word about how this layer stands, or empty. `off` for a network
    /// nothing can reach, `worktree` for the workspace it mounts.
    note: []const u8 = "",
    state: State,

    /// What became of one layer.
    ///
    /// **The names are the project's own**, from `chock_sandbox`'s cgroup
    /// support record: `ok`, `off`, `unsupported`, `unavailable`. Two of the
    /// four can be answered today and the other two are named here so that the
    /// answer has somewhere to land when it exists: see this file's own
    /// `Layer.State.unavailable`.
    pub const State = enum {
        /// The layer is on.
        on,
        /// The layer could be on and this session gave it up. The one case
        /// today is a network config of `.host`, which is allowed only for an
        /// act a user approved.
        off,
        /// This build's sandbox driver does not give this layer at all. Every
        /// layer on Darwin is this, and the driver refuses to run anything
        /// rather than run it unprotected.
        unsupported,
        /// The machine could give this layer and this process was not
        /// permitted. **Nothing produces this yet**, because no per layer
        /// record of a real `Sandbox.spawn` reaches this process: see
        /// `run.sandboxLayers`, which says what does reach it and why the
        /// remaining states are still honest.
        unavailable,

        /// The first signal: a glyph, which survives a terminal with no colour.
        pub fn glyph(self: State) []const u8 {
            return switch (self) {
                .on => "\u{2713}",
                .off, .unsupported, .unavailable => "\u{2717}",
            };
        }

        /// The second signal: the word, spelled out. No fact may rest on colour
        /// alone, and the word `OFF` goes beside the glyph for exactly this
        /// row.
        pub fn word(self: State) []const u8 {
            return switch (self) {
                .on => "",
                .off => "OFF",
                // A different word from `OFF`, because they are different
                // facts: one is a layer this session gave up and the other is a
                // layer this build never had. A person reading `NONE` knows
                // there is nothing to configure.
                .unsupported => "NONE",
                .unavailable => "BLOCKED",
            };
        }
    };
};

/// Where the narrow rules begin: under 60 columns this is a phone answering an
/// approval, and the header sheds layer names to glyphs.
pub const narrow_columns: u16 = 60;

/// How wide the plan sidebar is, stated in characters.
///
/// **Fixed and never a share of the display.** The rows in it are a status word
/// and a subject, so a sidebar that grew with the screen would put a short word
/// beside a wide gap. What a wide display gains is transcript, which is prose
/// and reads better wide, up to `readable_columns`.
///
/// **A count of characters and not a width**, for the reason
/// `readable_columns` gives. `Measure.step` turns it into a width for the face
/// in use, and nothing is ever fitted against it.
pub const sidebar_columns: u16 = 26;

/// The narrowest display the plan sidebar opens on.
///
/// **The design width, which is 80 columns, where everything must work.** A
/// second column is affordable there and is not below it, so this is the line:
/// at the design width the sidebar takes `sidebar_columns` and the transcript
/// keeps the rest, and under it the sidebar refuses to open at all. See
/// `Ui.togglePlan`, which says so and writes the plan into the transcript
/// instead.
pub const sidebar_needs_columns: u16 = 80;

/// What one step's status says in the sidebar.
///
/// **A word and never a mark.** No fact may rest on colour alone, and phantom's
/// `Icon` is worse than a colour here: `backend/tui_cells.zig` draws every icon
/// it has no cell glyph for as one solid block, so two statuses would be the
/// same square. A word survives a monochrome terminal, a colourblind reader,
/// and a pasted screen.
///
/// **Short, because the sidebar is 26 characters wide** and the subject needs
/// what is left. The wire names are what the transcript writes, where there is
/// room for them: see `Ui.sayPlan`.
pub fn statusWord(status: chock_proto.event.PlanStatus) []const u8 {
    return switch (status) {
        .pending => "next",
        .in_progress => "now",
        .done => "done",
        .abandoned => "stopped",
        // A status from a newer writer. **Never folded into any of the four**,
        // for the reason `state.Plan.Counts` counts it apart: an unrecognized
        // status is not finished work and it is not given up either.
        .unknown => "unknown",
    };
}

/// Whether the geometry a device just reported is a different geometry from
/// the one a session is drawing at.
///
/// **Asked because a resize is expensive and visible.**
/// `phantom.tui.Session.resize` clears the screen, throws away the front
/// buffer and rebases every image, so calling it on every frame would repaint
/// the whole display many times a second for nothing.
///
/// **The viewport and the ratio, and not the cell count.** Those are the two
/// numbers layout runs on: a terminal moved to a display with a different
/// resolution reports the same rows and columns and a different cell size, and
/// the rows on the screen have to be measured again. See
/// `phantom.tui.term.Size.viewport`.
pub fn sizeMoved(
    now: phantom.tui.term.Size,
    viewport: phantom.PhysicalSize,
    dpr: f32,
) bool {
    const box = now.viewport();
    return box.width != viewport.width or
        box.height != viewport.height or
        now.dpr() != dpr;
}

/// Whether a step is at `wanted`.
///
/// **A tag and not a value.** `PlanStatus` carries the text of a status this
/// build has no member for, so the union cannot be compared with `==` at all.
pub fn isStatus(
    status: chock_proto.event.PlanStatus,
    wanted: std.meta.Tag(chock_proto.event.PlanStatus),
) bool {
    return std.meta.activeTag(status) == wanted;
}

/// One row of the plan sidebar, and what it is, so the colour is chosen in one
/// place. See `HeaderPiece`, which is the same shape for the same reason.
pub const PlanLine = struct {
    text: []const u8,
    tone: Tone,

    pub const Tone = enum {
        /// The row that says what the region is and how much is done.
        title,
        /// The step being worked on now.
        now,
        /// Any other step.
        step,
        /// The row that says how many steps are not on the screen.
        aside,
    };
};

/// The plan sidebar, as rows of text, in `rows` rows or fewer.
///
/// **Pure, so what the sidebar says can be pinned without a display.** The
/// caller cuts each row to the region and gives it its colour: see
/// `Ui.sidebarRows`.
///
/// **The window follows the work.** A plan longer than the region shows the
/// first step that is not finished and everything after it, because a person
/// watching wants what is happening now and what is next. Finished steps
/// scroll off the top, and the row at the bottom says how many went. The same
/// argument `Ui.pickerRow` makes for a list that must show what is chosen.
///
/// **Nothing scrolls it, and that is deliberate.** The sidebar takes no keys,
/// so `Tab` and the arrows keep the meanings the key map gives them. A region
/// that took the keyboard would move where a keystroke lands, and where a
/// keystroke lands is a security surface.
pub fn planRows(
    arena: std.mem.Allocator,
    plan: chock_proto.state.Plan,
    rows: u16,
) std.mem.Allocator.Error![]const PlanLine {
    var out: std.ArrayList(PlanLine) = .empty;
    if (rows == 0) return out.items;

    const counts = plan.counts();
    // **The title never drops.** It is what says the region is the plan at all,
    // and on a region with one row it is the only honest thing to keep.
    try out.append(arena, .{
        .tone = .title,
        .text = if (counts.total() == 0)
            try std.fmt.allocPrint(arena, " plan   nothing yet", .{})
        else
            try std.fmt.allocPrint(arena, " plan   {d}/{d} done", .{
                counts.done,
                counts.total(),
            }),
    });

    const total: u16 = @intCast(@min(plan.steps.items.len, std.math.maxInt(u16)));
    var room = rows -| 1;
    // A region with one row is the title alone, and the title is the row that
    // says the region is the plan.
    if (room == 0) return out.items;

    // A row goes to saying what is not shown, and only when something is not
    // and a step would still fit beside it. On a region with room for one row
    // of plan that row is the work, not a count of it: the title already says
    // how many steps there are, so nothing is silent.
    const hides = total > room;
    if (hides and room > 1) room -= 1;

    var first: u16 = 0;
    while (first < total and isStatus(plan.steps.items[first].status, .done)) first += 1;
    // Backed up so the region is filled. A window that started at the first
    // unfinished step and left blank rows under it would show less than it has
    // room for.
    first = @min(first, total -| room);

    var at: u16 = first;
    while (at < total and at < first + room) : (at += 1) {
        const step = plan.steps.items[at];
        try out.append(arena, .{
            .tone = if (isStatus(step.status, .in_progress)) .now else .step,
            .text = try std.fmt.allocPrint(arena, " {s: <7} {s}", .{
                statusWord(step.status),
                step.subject,
            }),
        });
    }

    if (!hides or out.items.len >= rows) return out.items;
    const below = total -| at;
    try out.append(arena, .{
        .tone = .aside,
        // **A number and never a gap.** The same rule `Ui.ruleRow` follows for
        // the transcript: a count is a fact and an ellipsis reads as loss.
        .text = try std.fmt.allocPrint(arena, " {d} above, {d} below", .{ first, below }),
    });
    return out.items;
}

/// One run of the header, and what it is, so the colour is chosen in one place.
pub const HeaderPiece = struct {
    text: []const u8,
    tone: Tone,

    /// What a run of the header means. Each of these maps to a role, and the
    /// role to a colour per terminal tier.
    pub const Tone = enum {
        /// The program's own name.
        name,
        /// Project, workspace, model, provider: the context.
        context,
        /// A layer that is on.
        on,
        /// A layer that is not.
        off,
    };
};

/// How many columns a line of text takes on a character grid.
///
/// **A grid and never a face.** Counting columns is right for a caller that
/// states a width in columns and wrong for anything that lays out: see
/// `Measure.widthOf`, which is what the display measures a row with.
fn columnsOf(text: []const u8) f32 {
    return grid_measure.widthOf(text);
}

/// One layer, as the header writes it.
///
/// **Narrow sheds a name only when the layer is on.** Under 60 columns the
/// header sheds layer names to glyphs, and how it does that is open. A row of
/// bare glyphs would put the one fact a person is there for, a layer that is
/// not on, behind a glyph and a colour and nothing else, and no fact may rest
/// on colour alone. So an on layer becomes its glyph and a layer that is not
/// keeps its name and its word at every width.
pub fn layerText(
    arena: std.mem.Allocator,
    one: Layer,
    narrow: bool,
) std.mem.Allocator.Error![]const u8 {
    if (narrow and one.state == .on) return one.state.glyph();

    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, one.state.glyph());
    try text.append(arena, ' ');
    try text.appendSlice(arena, one.name);
    if (one.note.len != 0 and !narrow) {
        try text.append(arena, ' ');
        try text.appendSlice(arena, one.note);
    }
    const said = one.state.word();
    if (said.len != 0) {
        try text.append(arena, ' ');
        try text.appendSlice(arena, said);
    }
    return text.items;
}

/// The header line, in the order it is drawn.
///
/// **The layers are built first and keep their room.** The layers are the one
/// part of the header a person is there to see, and the rest is context. At 80
/// columns, which the design calls the design width, the context and the layers
/// together are wider than the row, so one of them has to go. A context fact
/// that does not fit whole is left off, and no layer ever is.
///
/// Appends to `into` and never clears it.
pub fn headerPieces(
    arena: std.mem.Allocator,
    facts: Facts,
    room: Room,
    into: *std.ArrayList(HeaderPiece),
) std.mem.Allocator.Error!void {
    const narrow = room.isNarrow();

    var layers: std.ArrayList(HeaderPiece) = .empty;
    var taken: f32 = 0;
    for (facts.layers) |one| {
        const said = try layerText(arena, one, narrow);
        const whole = try std.fmt.allocPrint(arena, "  {s}", .{said});
        taken += room.measure.widthOf(whole);
        try layers.append(arena, .{
            .text = whole,
            .tone = if (one.state == .on) .on else .off,
        });
    }

    var left = if (room.width > taken) room.width - taken else 0;
    const name = " chock";
    const named = room.measure.widthOf(name);
    if (named <= left) {
        left -= named;
        try into.append(arena, .{ .text = name, .tone = .name });
    }
    for ([_][]const u8{ facts.project, facts.workspace, facts.model, facts.provider }) |fact| {
        if (fact.len == 0) continue;
        const whole = try std.fmt.allocPrint(arena, "  {s}", .{fact});
        const width = room.measure.widthOf(whole);
        // **Whole or not at all**, because half a model name reads as a
        // different model. **And the rest goes with it**: a row that skipped
        // one fact and kept a shorter one after it would put the provider on a
        // header with no model, which reads as the model.
        if (width > left) break;
        left -= width;
        try into.append(arena, .{ .text = whole, .tone = .context });
    }

    for (layers.items) |one| try into.append(arena, one);
}

/// Who said a row of the transcript.
///
/// **An agent can never choose this.** It comes from which `Observer` call
/// delivered the text: `onPiece` and a `tool.call` event are the agent, a
/// notice and everything the harness records are Chock. The agent supplies the
/// words inside its own row and nothing else, which is what makes the split
/// structural rather than a matter of styling.
///
/// **The rule the two must keep**: Chock owns column 0 and the rail, and agent
/// content is always indented past it and never carries a rail. So an agent
/// that writes the word `chock:` at the start of its own text still writes it
/// at column 2, under no rail, and it reads as what it is.
pub const Voice = enum {
    chock,
    agent,

    /// What goes at the front of a row in this voice, before the agent's own
    /// words can begin.
    ///
    /// **Two signals and not one.** The rail is a glyph and the indent is a
    /// position, and both survive a terminal with no colour, a colourblind
    /// reader, and a transcript that was copied and pasted. Colour is the third
    /// signal and never the only one.
    pub fn prefix(self: Voice) []const u8 {
        return switch (self) {
            .chock => "\u{2502} ",
            .agent => "  ",
        };
    }
};

/// A pane over the transcript: rows a person reads, and how far down them they
/// have read.
///
/// **Chock's own words only.** A pane is not a region agent text may reach: the
/// agent has exactly one region and this is a surface over it, not part of it.
/// Everything a pane holds is written in this file.
///
/// **It scrolls, because that is what makes it a pane.** A screen too short for
/// the whole answer shows the first rows and says how many are left, and the
/// arrows reach the rest. Rows that do not fit are not lost and are not
/// silently cut.
pub const Pane = struct {
    /// Which of the pane's rows is drawn first. Never past the last row that
    /// can be at the top: see `hold`.
    at: u16 = 0,

    /// The rows of the pane, in order.
    kind: Kind,

    pub const Kind = enum { keys };

    /// Move the first shown row by `by`, with `room` rows on screen out of
    /// `total`.
    ///
    /// **Nothing runs off either end.** Scrolling down stops with the last row
    /// on screen rather than scrolling into blank rows, and scrolling up stops
    /// at the first. A pane one row too tall for the screen therefore has
    /// exactly one step in it.
    pub fn move(self: *Pane, by: i8, room: u16, total: u16) void {
        const last = total -| room;
        const now: i32 = self.at;
        const wanted = now + by;
        if (wanted < 0) {
            self.at = 0;
            return;
        }
        self.at = @min(@as(u16, @intCast(@min(wanted, std.math.maxInt(u16)))), last);
    }

    /// Put the first shown row back inside the pane after the screen changed
    /// size. A pane scrolled to the bottom of a short screen must not keep a
    /// blank half when the screen grows.
    pub fn hold(self: *Pane, room: u16, total: u16) void {
        self.at = @min(self.at, total -| room);
    }
};

/// One thing in the transcript that is shown as a line and kept whole
/// underneath: a tool result, a block of reasoning, a compaction, or a
/// subagent.
///
/// **This is the answer to a tool result that filled the screen.** A result is
/// one line, the fact first, the output behind a marker: 255/255 passed is the
/// fact, and 60 KB of build log is not. So the row a person reads is a summary
/// and the whole of it is one key away.
///
/// **A body is always the agent's own text**, whichever kind it is: a tool's
/// output, the model's reasoning, the summary a model wrote when the context
/// was folded, or what a subagent said. So every row of an open body is drawn
/// in the agent's voice, at the agent's indent, under no rail, and a fold can
/// never put agent bytes where Chock speaks. See `Voice`.
pub const Fold = struct {
    kind: Kind,
    /// The whole of it, as far as `Ui.kept_body_bytes`. Owned by the `Ui`.
    body: []const u8,
    /// How many bytes were past that bound and were not kept. **Counted rather
    /// than forgotten**, so the row under an open body says how much is not
    /// there. The words are always there, and never silence.
    dropped: usize = 0,
    /// Whether the body is on the screen. **Closed is the default**, which is
    /// the whole of the fix. `Space` is what opens one.
    open: bool = false,

    /// What is folded. `Space` opens these four: a tool result, a reasoning
    /// block, a compaction, and a subagent.
    ///
    /// **`o` is not built, and `subagent` is why this says so here.** `o` is to
    /// open the focused subagent and watch its session live, and `Esc` is the
    /// way back. That needs the child's own log read as it is written and a
    /// second transcript drawn from it, which is a session view and not a row.
    /// So the row exists, `Space` opens what this session was told, and the
    /// live view is named as missing rather than half made.
    pub const Kind = enum { result, reasoning, compaction, subagent };
};

/// What the right hand end of a foldable row says: whether it is open, and
/// which key changes that.
///
/// **The word moves as well as the glyph**, so the state does not rest on
/// colour, which no fact may do.
///
/// **The key is named on the row that has the focus.** That is the third thing
/// the marker says, and it is the rule an approval keeps and which costs
/// nothing here: the keys are on screen, and a user must never have to
/// remember.
///
/// **One marker, at the right, for all four kinds.** The design draws the
/// reasoning marker at the left of its own row and the others at the right. One
/// column the eye can run down is worth more than a copy of the drawing, and it
/// is the same argument the time column rests on.
pub fn markerText(open: bool, focused: bool) []const u8 {
    if (open) return if (focused) "\u{25be} hide  Space" else "\u{25be} hide";
    return if (focused) "\u{25b8} show  Space" else "\u{25b8} show";
}

/// One row with `left` at its start and `right` against its end, inside `room`.
///
/// **The right hand column is one the eye can ignore.** Time is on the right,
/// which is a column the eye can ignore: a duration on a tool call, and clock
/// time on a turn.
///
/// **The left is what is cut when the two cannot both fit**, because the right
/// is a duration, a clock, or a marker, and half of any of the three reads as a
/// different value.
pub fn spread(
    arena: std.mem.Allocator,
    left: []const u8,
    right: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    if (right.len == 0) return visibleLine(arena, left, room);
    const pinned = room.measure.widthOf(right);
    // **Cut even here**, because a row that ran past the edge would wrap and
    // the wrapped part would start at column 0, where only Chock draws. See
    // `Ui.voicedRow`.
    if (pinned >= room.width) return visibleLine(arena, right, room);

    // One space between the two at the very least, so the left never touches
    // the right.
    const gap = room.measure.advanceOf(' ');
    const cut = try visibleLine(arena, left, room.upTo(room.width - pinned - gap));
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, cut);
    // Spaces up to where the right hand piece begins. **A face with no column
    // cannot land it exactly**, which is why a row with a marker on it is laid
    // out again by `Ui.pinnedRow`. This is what that same row measures as, and
    // the two must agree about what the words are.
    const starts = room.width - pinned;
    var filled = room.measure.widthOf(cut);
    while (filled + gap <= starts) : (filled += gap) try out.append(arena, ' ');
    try out.appendSlice(arena, right);
    return out.items;
}

/// How long a tool call took, written as `18.2s` or `0.1s`.
///
/// **A settled duration is the second signal on a call that finished.** A call
/// that worked shows the glyph and a settled duration, so the number is there
/// whether or not anything went wrong.
pub fn durationText(arena: std.mem.Allocator, ms: i64) std.mem.Allocator.Error![]const u8 {
    // A clock that went backwards is a wrong clock and never a negative
    // duration. See `Ui.clock`, which is the machine's own real time.
    const took: u64 = if (ms <= 0) 0 else @intCast(ms);
    if (took < 60 * 1000) {
        return std.fmt.allocPrint(arena, "{d}.{d}s", .{ took / 1000, (took % 1000) / 100 });
    }
    const seconds = took / 1000;
    return std.fmt.allocPrint(arena, "{d}m{d:0>2}s", .{ seconds / 60, seconds % 60 });
}

/// How much of something there is, written as `2.1 KB of reasoning`.
pub fn sizeText(arena: std.mem.Allocator, bytes: usize) std.mem.Allocator.Error![]const u8 {
    if (bytes < 1024) return std.fmt.allocPrint(arena, "{d} B", .{bytes});
    if (bytes < 1024 * 1024) {
        return std.fmt.allocPrint(arena, "{d}.{d} KB", .{ bytes / 1024, (bytes % 1024) * 10 / 1024 });
    }
    const mb = bytes / (1024 * 1024);
    const rest = bytes % (1024 * 1024);
    return std.fmt.allocPrint(arena, "{d}.{d} MB", .{ mb, rest * 10 / (1024 * 1024) });
}

/// The last moment `clockText` states, 9999-12-31 23:59:59 UTC. The same bound
/// `chock_core.notices` keeps, and for the same reason: a clock is a runtime
/// fact and a number far past any real date must not print a strange year.
const last_second: u64 = 253402300799;

/// The time of day a turn began, written as `12:04`.
///
/// **Local, because the question a clock in a transcript answers is local.**
/// `offset_minutes` is minutes east of UTC, read from the machine's own zone
/// database by `src/clock.zig`, and zero is the honest answer for a machine
/// that did not say.
pub fn clockText(
    arena: std.mem.Allocator,
    epoch_ms: i64,
    offset_minutes: i32,
) std.mem.Allocator.Error![]const u8 {
    const shifted = @divFloor(epoch_ms, 1000) + @as(i64, offset_minutes) * 60;
    const seconds: u64 = if (shifted < 0) 0 else @min(@as(u64, @intCast(shifted)), last_second);
    const day = (std.time.epoch.EpochSeconds{ .secs = seconds }).getDaySeconds();
    return std.fmt.allocPrint(arena, "{d:0>2}:{d:0>2}", .{
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
    });
}

/// The keys of a tool call's arguments this reads, in the order it prefers
/// them.
///
/// **Named rather than guessed.** Each one is a field of a real tool's
/// arguments in `chock_core.tools`: `path` on `read_file`, `pattern` on `grep`
/// and `glob`, `name` on `read_memory`, `program` on `provide_tool`,
/// `agent_kind` on `spawn_agent`, `action` on `restrict_self`. A tool this list
/// does not cover falls back on its own single argument, and then on the JSON.
const argument_keys = [_][]const u8{
    "pattern",
    "path",
    "name",
    "program",
    "agent_kind",
    "action",
};

/// A tool call's arguments, as a person reads them: `zig build test`, and never
/// `{"argv":["zig","build","test"]}`.
///
/// **The argument is what says which call this is.** A transcript of six
/// `run_command` rows with the JSON cut at the edge is six identical rows, and
/// the one thing a person is looking for is which command each one ran.
///
/// **Nothing is invented when the shape is not known.** Arguments this cannot
/// read come back as the JSON they arrived as, cut to the row like every other
/// agent supplied string. A wrong reading would be worse than a raw one.
pub fn argumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return arguments;
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return arguments,
    };

    // `run_command`, which is the one a person reads most and the one the
    // design draws: the program and its arguments, spaced, as they were run.
    if (object.get("argv")) |argv| {
        if (argv == .array) {
            var out: std.ArrayList(u8) = .empty;
            for (argv.array.items) |item| {
                if (item != .string) continue;
                if (out.items.len != 0) try out.append(arena, ' ');
                try out.appendSlice(arena, item.string);
            }
            if (out.items.len != 0) return out.items;
        }
    }

    var out: std.ArrayList(u8) = .empty;
    for (argument_keys) |key| {
        const value = object.get(key) orelse continue;
        if (value != .string or value.string.len == 0) continue;
        if (out.items.len != 0) try out.append(arena, ' ');
        try out.appendSlice(arena, value.string);
    }
    if (out.items.len != 0) return out.items;

    // A tool with one string argument and a name this file does not know: the
    // value is still what says which call it is.
    var only: ?[]const u8 = null;
    var members = object.iterator();
    while (members.next()) |member| {
        if (member.value_ptr.* != .string) continue;
        if (only != null) return arguments;
        only = member.value_ptr.string;
    }
    return only orelse arguments;
}

/// The one line of an `ask_user` call a person reads: the question itself.
///
/// **A case of its own, because the general reading gets this one wrong.**
/// `argumentText` has no tool name to go on, and an `ask_user` call carries a
/// question and a list, which is two members and no known key, so it fell all
/// the way through to the raw JSON. A person watching a session then read
/// `{"question":"which database?","options":["a","b"]}` on the row where the
/// question should have been, and the question is the whole of what that call
/// is.
///
/// **The words are the model's**, so the row they land on is an agent row at
/// the agent's indent under no rail, exactly as every other tool call row is:
/// see `Ui.beginCall`, and `Voice`.
///
/// **Nothing is invented when the shape is not known.** A call whose arguments
/// do not parse comes back as `argumentText` read them, which is the raw JSON,
/// because a wrong reading is worse than a raw one.
pub fn askArgumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return argumentText(arena, arguments);
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return argumentText(arena, arguments),
    };
    const question = object.get("question") orelse return argumentText(arena, arguments);
    if (question != .string or question.string.len == 0) return argumentText(arena, arguments);

    // A question is several sentences often enough, and a row is one line. The
    // whole of it is in the region while it is open and in the log for ever, so
    // the row carries the first line and says nothing about the rest.
    const first = question.string[0 .. std.mem.indexOfScalar(u8, question.string, '\n') orelse
        question.string.len];

    const options = object.get("options") orelse return first;
    if (options != .array or options.array.items.len == 0) return first;
    return std.fmt.allocPrint(arena, "{s}  ({d} to choose from)", .{
        first,
        options.array.items.len,
    });
}

/// The one line of a tool result a person reads, derived from the result
/// itself.
///
/// **The exit status leads.** git prints the word error on a line and still
/// succeeds, so the status is authoritative and the text is not. A call that
/// failed says `exit 128` before it says anything the program printed.
///
/// **A call that worked is summarised by its last line**, because that is where
/// a build, a test run, or a search puts its verdict: `255/255 passed`. A call
/// that failed is summarised by its first, because that is where the reason is.
///
/// **A note Chock itself put on the front of the output is the summary when
/// there is one.** `read_file` answers with `[chock: 62144 bytes, file_hash
/// ...]` and then the file, and the note is the fact about the call.
///
/// **This is derived and never authored.** The words come from the result and
/// the result is the agent's, so this line is drawn at the agent's indent under
/// no rail: see `Ui.finishCall`.
pub fn summaryText(
    arena: std.mem.Allocator,
    output: []const u8,
    is_error: bool,
    truncated: bool,
) std.mem.Allocator.Error![]const u8 {
    var rest = output;
    var lead: []const u8 = "";

    // `chock_core.tools` puts this line in front of every command's own bytes.
    const status_prefix = "exit status: ";
    if (std.mem.startsWith(u8, rest, status_prefix)) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const code = rest[status_prefix.len..at];
        // Zero is not said: a call that worked shows no status at all, and one
        // that failed shows the status first.
        if (!std.mem.eql(u8, code, "0")) {
            lead = try std.fmt.allocPrint(arena, "exit {s}", .{code});
        }
        rest = if (at == rest.len) rest[at..] else rest[at + 1 ..];
    }

    const failed = is_error or lead.len != 0;
    var said = if (failed) firstLine(rest) else lastLine(rest);
    // Chock's own note about the call, which is the fact when there is one.
    const note = firstLine(rest);
    if (std.mem.startsWith(u8, note, "[chock: ") and std.mem.endsWith(u8, note, "]")) {
        said = note["[chock: ".len .. note.len - 1];
    }

    var out: std.ArrayList(u8) = .empty;
    if (lead.len != 0) try out.appendSlice(arena, lead);
    if (said.len != 0) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, said);
    }
    // A truncated result says so in words, and never in silence.
    if (truncated) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, "output truncated");
    }
    if (out.items.len == 0) return "no output";
    return out.items;
}

/// The first line of `text` that holds anything, or empty.
fn firstLine(text: []const u8) []const u8 {
    var rest = text;
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) return line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return "";
}

/// The last line of `text` that holds anything, or empty.
fn lastLine(text: []const u8) []const u8 {
    var rest = text;
    var found: []const u8 = "";
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) found = line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return found;
}

/// A command a person types into the input band instead of a message.
///
/// **Not in the key map.** The key map is a single letter model and no
/// `/command` appears anywhere in it. This is an addition the project owner
/// asked for, and it is written down here rather than folded in silently.
///
/// **A slash command never reaches the model.** It is the harness's: no part of
/// the typed line becomes a user message, and no event carries it. That is the
/// same rule the transcript rail encodes from the other side, and `runCommand`
/// is where it is kept.
pub const Command = enum {
    help,
    plan,
    usage,
    @"resume",

    /// What a person types, with the slash.
    pub fn typed(self: Command) []const u8 {
        return switch (self) {
            .help => "/help",
            .plan => "/plan",
            .usage => "/usage",
            .@"resume" => "/resume",
        };
    }

    /// What the completion list says it does.
    pub fn does(self: Command) []const u8 {
        return switch (self) {
            .help => "every key, and every command",
            .plan => "the plan, kept at the side of the screen",
            .usage => "the tokens and the cost so far",
            .@"resume" => "end this session and take up another",
        };
    }

    pub const all = [_]Command{ .help, .plan, .usage, .@"resume" };
};

/// The command a whole line names, or null when the line is a message.
///
/// **The whole line has to be a command and nothing else.** That is the rule,
/// and it is the rule because of one ordinary line: `/home/ross/chock/src/
/// main.zig is broken` is a thing a person really types at a coding agent. A
/// "line begins with a slash" rule would swallow it and send nothing.
///
/// Matching the first word alone would not be enough either: `/help me
/// understand this` opens with a word that is a command and is plainly a
/// message. Requiring the whole line leaves both of those as messages, and it
/// costs nothing, because no command here takes an argument.
///
/// **When one does, this rule has to be looked at again**, and the answer will
/// have to keep `/help me understand this` a message. It is written here rather
/// than left to be rediscovered.
///
/// **And the list is the live proof of it.** While what is typed is the start of
/// a command the list is open; the moment it is not, the list closes. A person
/// typing `/ho` watches it close and can see that this line is a message. See
/// `completions`.
pub fn commandOf(line: []const u8) ?Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return null;
    for (Command.all) |one| {
        if (std.mem.eql(u8, trimmed, one.typed())) return one;
    }
    return null;
}

/// "yes" or "no", for a line a person reads.
fn yesNo(answer: bool) []const u8 {
    return if (answer) "yes" else "no";
}

/// One session `/resume` offers, and whether it can be taken.
///
/// **Whether it can be taken is worked out when the list is built**, not when a
/// person chooses. A list that showed every session and then refused half of
/// them on Enter would make a person guess; this one says so on the row.
pub const Resumable = struct {
    /// The session identifier. Owned by the display's arena.
    id: []const u8,
    /// The row a person reads: when it started, and how it ended.
    words: []const u8,
    /// Empty when it can be taken. Why it cannot, otherwise.
    refusal: []const u8 = "",
};

/// The question the approval region is showing.
///
/// **Copied in, never borrowed.** The question is read out of the session log
/// by whoever is waiting for the answer, and that reader's parse ends long
/// before a person has read the screen. See `Ui.showApproval`, which owns every
/// string here in an arena of its own.
///
/// **Three of these fields are the agent's own words**: `summary`, `reason` and
/// `detail`. They are shown inside the region and nothing else about the region
/// comes from them, so an agent supplies the words in its own block and cannot
/// reach the action, the chain, the countdown, or the row that names the keys.
/// That is the same split `Voice` makes in the transcript. Every row is cut by
/// `visibleLine`, so a control byte in a diff becomes a space and a long line
/// stops at the edge.
pub const Approval = struct {
    /// The `approval.request` this is about, so an answer names the question it
    /// answers.
    request_id: u64,
    /// The action, by the name the policy table gives it.
    action: []const u8,
    /// The one line form of the effect. The agent's own words.
    summary: []const u8,
    /// Why the agent wants this. The agent's own words.
    reason: []const u8,
    /// Every agent between the root and the one that asked, joined for reading.
    chain: []const u8,
    /// How deep the agent that asked is. This is kept at every width, because
    /// "a subagent three levels down asked for this" changes the answer.
    depth: usize,
    /// The effect at length: a diff, usually. The agent's own words.
    detail: []const u8,
    /// What a reviewer already said, or empty.
    review: []const u8 = "",
    /// How long is left, in milliseconds, as the waiter last measured it.
    left_ms: i64 = 0,
    /// Which of the three views the region is showing.
    view: View = .question,

    /// What the region is showing. `d` and `w` each get a view, and answering
    /// stays available from inside them.
    pub const View = enum {
        /// The question: action, chain, summary, reason, effect, keys.
        question,
        /// The whole of `detail`.
        diff,
        /// The spawn chain in full.
        why,
    };
};

/// What a person said about a question.
///
/// **Two letters and no default.** An approval never has a default and never
/// has a held key. The two answers are separate letters, and neither is Enter.
pub const Answered = enum { approved, refused };

/// How one look at the approval region ended. See `Ui.awaitAnswer`.
pub const Look = union(enum) {
    /// Nothing was said. Look again.
    waiting,
    /// The person answered.
    answered: Answered,
    /// The session is being stopped: Ctrl-C, or a display that went away.
    /// Nothing was decided, and the question stays open in the log.
    canceled,
};

/// One question the agent asked, as the region shows it.
///
/// **This is not an `Approval` and it must never become one.** An approval asks
/// "may I do this act": it names one `chock_broker.actions` action, the policy
/// table weighs it, and the answer is a decision recorded against that act. A
/// question wants a fact a person holds, and **answering one permits nothing**.
/// The two regions look alike because they are both a raised panel with a
/// deadline, and that is the whole of what they share: there is no member here
/// that could name an act, and no answer this region can produce that authorises
/// anything. `lib/chock-core/ask.zig`'s own top comment says at length why a
/// later reader must not join the two.
///
/// **Every string is copied**, into `Ui.question_arena`: the caller read them
/// out of a tool call whose parse ends when it returns, and a person has not
/// read the screen yet.
///
/// **`text` and `options` are the model's own words and are untrusted.** They
/// are written after `chock_core.ask.question_marker` and nowhere else, so no
/// byte the model chose can start a row of the region: see
/// `Ui.questionRegion`.
pub const Question = struct {
    /// Which agent asked. Chock's own word for it, never the model's.
    agent_kind: []const u8 = "",
    /// What the model wants to know, in its own words.
    text: []const u8,
    /// The answers the model would like to be given, or none. **Never a closed
    /// list**: a person types whatever they like. The model's own words.
    options: []const []const u8 = &.{},
    /// How long is left, in milliseconds, as the asker last measured it.
    left_ms: i64 = 0,
};

/// How one look at the question region ended. See `Ui.awaitText`.
///
/// **There is no member that permits anything**, which is the same guard
/// `chock_core.ask.Answer` carries and for the same reason: the most an answer
/// can be is words.
pub const Text = union(enum) {
    /// Nothing was said. Look again.
    waiting,
    /// The session is being stopped: Ctrl-C, or a display that went away.
    canceled,
    /// What the person typed, or the option they chose by number. **Borrowed**,
    /// and valid until the next call on this display: the caller copies it.
    answered: []const u8,
    /// The person pressed Enter with nothing typed. A deliberate "no answer",
    /// which is a different fact from nobody being there.
    declined,
};

/// The keys the question region writes on itself when the model offered a list.
///
/// **On screen, always**, the same rule `approval_keys` follows: a person under
/// a deadline must not have to remember anything. The last clause is the one
/// fact that separates this region from the one above it, so it is on the row
/// that is drawn first and dropped last.
pub const question_keys = " [1-9] choose  [Enter] send, or send nothing.  Answering allows nothing.";

/// The same row for a question with no list to choose from.
pub const question_keys_open = " [Enter] send, or send nothing.  Answering allows nothing.";

/// The same two rows on a screen too narrow for the words above.
pub const question_keys_narrow = " [1-9] choose  [Enter] send.  Allows nothing.";
pub const question_keys_open_narrow = " [Enter] send.  Allows nothing.";

/// The keys row for a question this wide, with or without a list.
pub fn questionKeys(room: Room, has_options: bool) []const u8 {
    if (room.isNarrow()) return if (has_options) question_keys_narrow else question_keys_open_narrow;
    return if (has_options) question_keys else question_keys_open;
}

/// How many lines a piece of text holds, counting one for text with no line
/// feed in it at all.
///
/// **A count and not a split**, because the caller wants a row count before it
/// has an arena to split into. Empty text is one line: an empty question still
/// takes a row, and a region that gave it none would show a header with nothing
/// under it.
pub fn countLines(text: []const u8) usize {
    return 1 + std.mem.count(u8, text, "\n");
}

/// How long `text` is with its last whole character taken off.
///
/// **A whole character and not a byte.** A backspace over a letter that takes
/// three bytes must take all three, or what is left is half a character, which
/// phantom cannot measure and a provider answers 400 to.
pub fn backOne(text: []const u8) usize {
    if (text.len == 0) return 0;
    var at = text.len - 1;
    // Every byte of a multi byte character after the first is 0b10xxxxxx, so
    // this walks back to the byte that starts the character.
    while (at != 0 and text[at] & 0b1100_0000 == 0b1000_0000) at -= 1;
    return at;
}

/// Copy a list of options into `arena`. An option that could not be copied is
/// dropped, and a list that could not be built at all is empty: a question with
/// no list is still a question a person can answer in their own words.
fn dupeOptions(arena: std.mem.Allocator, options: []const []const u8) []const []const u8 {
    var kept: std.ArrayList([]const u8) = .empty;
    for (options) |option| {
        const one = arena.dupe(u8, option) catch continue;
        kept.append(arena, one) catch return kept.items;
    }
    return kept.items;
}

/// What the person's own answer is typed after.
///
/// **Chock's own bytes at column zero of the row**, so the line a person is
/// typing on cannot be mistaken for a line of the model's: every one of those
/// starts with `chock_core.ask.question_marker` instead.
pub const answer_prompt = " > ";

/// What goes where the keys would, on a display that cannot take one.
///
/// **Honest and visible beats keys that do nothing.** A window has no device
/// here and a terminal that refused raw mode has no bounded read, so neither can
/// answer. Unlike an approval there is no second road to an answer: an ask
/// travels over no socket, so nothing else can answer it and the deadline is
/// what ends it. See `chock_core.ask`'s own top comment.
pub const question_unanswerable = " nobody can answer here. The agent is told so when the time runs out.";

/// The keys the approval region answers, as it writes them on itself.
///
/// **On screen, always.** That is a rule of its own: an approval shows its own
/// keys in its own region, and a user must never have to remember, or press `?`
/// under a deadline.
pub const approval_keys = " [y] approve  [n] refuse  [d] diff  [w] why";

/// The same four keys on a screen too narrow for the words above.
///
/// **Shorter words, never fewer keys.** The header sheds layer names under 60
/// columns and this is the same idea, but the rule above is absolute: a row
/// that dropped `[w] why` at 50 columns would be a person who cannot see why
/// they are being asked, on the very screen that is a phone answering an
/// approval.
pub const approval_keys_narrow = " [y] yes  [n] no  [d] diff  [w] why";

/// The keys row for a screen this wide.
pub fn approvalKeys(room: Room) []const u8 {
    return if (room.isNarrow()) approval_keys_narrow else approval_keys;
}

/// What goes where the keys would, on a display that cannot take one.
///
/// **Honest and visible beats four keys that do nothing.** A window has no
/// device here and a terminal that refused raw mode has no bounded read, so
/// neither can answer. The question is still in the session log and a client on
/// the approval socket can still answer it, so this names the command that
/// does. See `Ui.answersKeys`, and `src/approve.zig`.
///
/// **The identifier is dropped rather than cut when the row is too narrow, and
/// what is left is still a working command.** `chock approve` with no session
/// attaches to the newest session of this project, which is this one. A cut
/// identifier would be a command that names a session nobody has.
pub fn elsewhereText(
    arena: std.mem.Allocator,
    session: []const u8,
    room: Room,
) []const u8 {
    const short = " answer it with: chock approve";
    if (session.len == 0) return short;
    const whole = std.fmt.allocPrint(arena, "{s} {s}", .{ short, session }) catch return short;
    return if (room.holds(whole)) whole else short;
}

/// How many looks an arriving approval ignores the keyboard for.
///
/// **This is a security property**: an arriving approval must not steal a
/// keystroke already in flight, so input is ignored for a moment after it
/// appears. A person who was pressing `y` at a completion list a moment ago
/// must not find they approved a push with it.
///
/// **Counted in looks and not in milliseconds**, so the rule can be pinned by a
/// test with no clock in it. One look is bounded by the terminal's own `VTIME`
/// of a tenth of a second, so three of them is about a third of a second: see
/// `Ui.awaitAnswer`.
pub const settle_looks: u8 = 3;

/// A countdown in minutes and seconds, written as `0:42`.
///
/// **A number that moves is the second signal.** An expiring approval gets a
/// counting number and a position, so the fact does not rest on the colour it
/// turns.
pub fn countdownText(arena: std.mem.Allocator, left_ms: i64) std.mem.Allocator.Error![]const u8 {
    if (left_ms <= 0) return "0:00";
    const seconds: u64 = @intCast(@divFloor(left_ms + 999, 1000));
    return std.fmt.allocPrint(arena, "{d}:{d:0>2}", .{ seconds / 60, seconds % 60 });
}

/// How many Ctrl-C presses are in a run of bytes read from the terminal.
///
/// **Raw mode turns `ISIG` off, so a press arrives as a byte and no `SIGINT` is
/// sent.** `Ui.awaitAnswer` puts the signal back and raises it once for each
/// press it counts here, so Ctrl-C keeps exactly the meaning
/// `src/interrupt.zig` gives it: the first press stops the session at its next
/// safe point, and the second ends every running tool call and leaves. See
/// `Ui.awaitAnswer` for the ordering that makes that true.
///
/// **`0x03` cannot be part of anything else.** Every escape sequence a terminal
/// sends starts at `0x1b`, so a byte of this value in a read is a press and
/// never the middle of a key.
pub fn ctrlCPresses(bytes: []const u8) usize {
    return std.mem.count(u8, bytes, &.{0x03});
}

/// The terminal's own settings, with the echo taken out of them.
///
/// **This is the state a turn runs in.** `ISIG` and `ECHO` are independent bits
/// of `c_lflag`, and only `ISIG` has to come back between the two spans this
/// file reads the keyboard for: that is what lets `src/interrupt.zig` own
/// Ctrl-C during a turn, and what lets a second press reach
/// `chock_core.tools.cancelRunningTool`. `phantom.tui.term.Term.leaveRaw`
/// restores every bit it saved, the echo included, so a turn used to run with
/// the echo on and a display that prints whatever the terminal sends at it. A
/// scroll wheel on the alternate screen sends arrow escape sequences, so a
/// wheel wrote `^[[A` across the transcript.
///
/// **Two bits change and no others.** `ICANON`, `OPOST` and the rest stay as the
/// person had them, so the line `src/interrupt.zig` writes from a signal handler
/// still reads as a line, and a terminal put back by `dropKeys` is put back
/// exactly.
///
/// **`ECHONL` as well as `ECHO`.** A terminal in canonical mode echoes a newline
/// through `ECHONL` even with `ECHO` off, and a newline moves the whole screen.
pub fn quietOf(was: std.posix.termios) std.posix.termios {
    var quiet = was;
    quiet.lflag.ECHO = false;
    quiet.lflag.ECHONL = false;
    return quiet;
}

/// Write settings straight at a device, with no seam.
///
/// **For the paths that put a terminal back when a start failed**, where there
/// is no `Ui` yet to hold the seam `apply_termios` is. A device that refuses is
/// a device that has gone, and a start that is already failing must not fail
/// twice over it.
fn putTermios(handle: std.posix.fd_t, settings: std.posix.termios) void {
    std.posix.tcsetattr(handle, .FLUSH, settings) catch {};
}

/// What one turn of `Ui.askForMessage` came back with.
///
/// **Three outcomes and not two.** A session that is being left and a session
/// that is being taken up are different things for `src/run.zig` to do, and one
/// answer that meant both would make the caller guess.
pub const Ask = union(enum) {
    /// The person is done: an empty line, Ctrl-C at the field, or a display that
    /// stopped. The session ends the way it always does.
    done,
    /// Send this to the model.
    message: []const u8,
    /// End this session cleanly and take up the one with this identifier. See
    /// `Ui.takePicked`, and `src/run.zig` for what happens next.
    take_up: []const u8,
};

/// What a finished line turns out to be.
pub const Answer = union(enum) {
    /// Nothing was typed. The person is done: see `Ui.askForMessage`.
    nothing,
    /// The harness's to answer, and no part of it goes any further.
    command: Command,
    /// The model's to answer.
    message: []const u8,
};

/// Read one finished line.
///
/// **The one place a command is told apart from a message**, so the rule is in
/// one function a test can reach rather than spread through the loop that reads
/// the keyboard. `Ui.askForMessage` is its only caller, and it returns only the
/// `message` arm: a command never becomes a user message, an event, or anything
/// the model sees.
pub fn answerFor(line: []const u8) Answer {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return .nothing;
    if (commandOf(trimmed)) |command| return .{ .command = command };
    return .{ .message = trimmed };
}

/// Every command whose name starts with what has been typed, for the list.
///
/// **Empty for anything that is not a slash and a prefix**, which is what
/// closes the list and tells a person their line is a message.
pub fn completions(line: []const u8, into: []Command) []const Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return into[0..0];
    // A command with an argument after it has been chosen already.
    if (std.mem.indexOfScalar(u8, trimmed, ' ') != null) return into[0..0];

    var found: usize = 0;
    for (Command.all) |one| {
        if (found == into.len) break;
        if (!std.mem.startsWith(u8, one.typed(), trimmed)) continue;
        into[found] = one;
        found += 1;
    }
    return into[0..found];
}
/// One row of the transcript, whose voice it is in, and what it keeps folded
/// under it.
const Line = struct {
    voice: Voice,
    /// Owned by the `Ui` that holds it.
    text: []const u8,
    /// The value held against the right hand end of this row: a clock on a
    /// header, a duration on a tool call. Empty for a row that has none, and
    /// owned by the `Ui` as `text` is.
    ///
    /// **Carried and never pasted on.** Padding the value out with spaces
    /// fixes it to the width the row was built at, and a window that then grew
    /// narrower wrapped the value on to a row of its own. A row that carries
    /// the value is laid out again every frame, at whatever the room is now:
    /// see `Ui.voicedRow` and `Ui.pinnedRow`, which the fold marker has always
    /// gone through for the same reason.
    pinned: []const u8 = "",
    /// What this row opens to show, or null for an ordinary row. Its body is
    /// owned by the `Ui` too. See `Fold`.
    fold: ?Fold = null,
    /// Whether this row is the blank row Chock puts between two blocks.
    ///
    /// **A gap is structure and an empty line is content, and they are not the
    /// same row.** There is one blank line between blocks and never two, and
    /// that blank row is Chock separating two things it drew. A blank line the
    /// agent itself wrote is the agent's own content and keeps the agent's
    /// indent, exactly as its words do.
    ///
    /// **Only `Ui.startBlock` sets this**, and nothing an agent says reaches it,
    /// so an agent cannot produce the break that separates its words from
    /// Chock's. See `Voice`.
    gap: bool = false,
};

/// One row of the transcript as it is drawn, which is not the same thing as one
/// `Line`: an open fold puts its body on rows of its own underneath its head.
///
/// **Built for a frame and thrown away with it.** Nothing here is state: the
/// state is `Line.fold.open`, and this is what that state looks like.
const Shown = struct {
    voice: Voice,
    text: []const u8,
    /// The value held against the right hand end, from the `Line` this row came
    /// from. **On the first row of a wrapped line only**, where the fold marker
    /// also goes. See `Line.pinned`.
    pinned: []const u8 = "",
    /// Which `Line` this row can open and close, when it is the row that can.
    /// Null for an ordinary row and for every row of a body.
    fold_at: ?usize = null,
    open: bool = false,
    /// The blank row between two blocks. See `Line.gap`: it carries no voice
    /// structure at all, because it is not something anybody said.
    gap: bool = false,
};

/// The one running phantom session, whichever backend it is.
///
/// **The two are driven identically**, which is the whole reason phantom split
/// them the same way: `init`, `step` until it says stop, then `deinit`. So this
/// is a union of two pointers and four one line methods, and not a second
/// implementation of anything.
const Surface = union(enum) {
    terminal: *phantom.tui.Session,
    window: *phantom.window.Session,

    fn step(self: Surface) !bool {
        return switch (self) {
            .terminal => |one| one.step(),
            .window => |one| one.step(),
        };
    }

    /// One step that gives the display up to `wait_ms` to bring an event back.
    ///
    /// **For a look that has nothing else to bound it.** Every wait in this
    /// file is a loop of looks, and what makes one look take a tenth of a
    /// second rather than no time at all is the keyboard device: `enterRaw`
    /// sets `VMIN 0` and `VTIME 1`, so the read at the end of a look comes back
    /// within that tenth whether or not a key arrived. **A window has no such
    /// device.** Phantom delivers its keys through the compositor connection,
    /// so a window look reads nothing, waits for nothing, and comes back at
    /// once. Measured on weston: a window waiting for the first message spent
    /// 99 percent of a core on that loop.
    ///
    /// **A thread is not the answer and must never become one.** See
    /// `chock_core.idle`: the sandbox needs a single threaded caller. So the
    /// wait goes where the loop already is, in the compositor poll the step
    /// makes anyway.
    ///
    /// **The terminal arm ignores `wait_ms`, and that is not an oversight.**
    /// Its own device is the bound and it is the shorter of the two, so a wait
    /// here would only be a second one after it.
    ///
    /// **`poll_ms` is put back on every path.** `windowOptions` states zero for
    /// the running session, because a display must not pace a turn, and this
    /// widens it for the length of one look and no longer.
    fn stepWaiting(self: Surface, wait_ms: u32) !bool {
        switch (self) {
            .terminal => |one| return one.step(),
            .window => |one| {
                const was = one.opts.poll_ms;
                one.opts.poll_ms = wait_ms;
                defer one.opts.poll_ms = was;
                return one.step();
            },
        }
    }

    fn deinit(self: Surface) void {
        switch (self) {
            .terminal => |one| one.deinit(),
            .window => |one| one.deinit(),
        }
    }

    /// Forget what is on the display, so the next frame draws every part of it.
    ///
    /// **Only the terminal needs this**, and it is not an oversight that the
    /// window does not: the thing it repairs is a line printed straight at the
    /// terminal under a display that keeps a copy of every cell. A window has no
    /// such neighbour. See `src/tty.zig`'s `scrolled`.
    fn invalidate(self: Surface) void {
        switch (self) {
            .terminal => |one| one.invalidate(),
            .window => {},
        }
    }

    /// Take the terminal's own geometry, if it has changed since the last
    /// frame. Null for a window, whose own session already takes the
    /// compositor's report.
    fn terminalSession(self: Surface) ?*phantom.tui.Session {
        return switch (self) {
            .terminal => |one| one,
            .window => null,
        };
    }

    /// Put the keyboard focus on the last region that can take it.
    ///
    /// **Backwards, and that is the whole trick.** The regions take focus in
    /// the order they are drawn, so the transcript is first. Phantom's
    /// `focusPrev` from nothing focused lands on the last of them, and which
    /// region that is says what this call means:
    ///
    /// * **While a message is wanted** the field is last, so a person can type
    ///   the moment the display is up and `Tab` moves from there.
    /// * **While a question is open** there is no field, the approval region is
    ///   last, and that is what is wanted: the region takes the focus on
    ///   arrival, so `y` means approve only there.
    ///
    /// **Both sessions own a focus manager and both are asked**, which they have
    /// not always been: the window arm was empty while phantom carried the
    /// manager on the terminal session alone, and it is filled now that
    /// `phantom.window.Session` carries one too.
    ///
    /// **On a window the call is necessary and it is not sufficient**, and the
    /// difference is an ordering one. `focusPrev` walks the order the manager
    /// holds, and that order is built by `focus_mgr.collect`, which phantom runs
    /// inside a frame. A terminal draws a frame on every `step`, so the order
    /// exists by the time anything here asks for it. A window draws only when
    /// the compositor grants a frame, so an early call finds an empty order, and
    /// `focusPrev` on an empty order returns having done nothing and says
    /// nothing about it. Measured on weston: the window came up with the field
    /// unfocused, and a person had to press `Tab` twice before one letter of
    /// theirs arrived.
    ///
    /// **So a caller asks until it takes, and `hasFocus` is how it knows.**
    /// `awaitAnswer` and `awaitText` already did that for their own regions, and
    /// `askForMessage` does it now for the field. That is the whole of the fix
    /// on this side, and it holds whatever phantom later does about the order it
    /// builds.
    fn focusLast(self: Surface) void {
        switch (self) {
            .terminal => |one| one.focus_mgr.focusPrev(),
            .window => |one| one.focus_mgr.focusPrev(),
        }
    }

    /// Whether any region holds the keyboard focus at this moment.
    ///
    /// **What a claim that did not take looks like from outside.**
    /// `focusPrev` on an order that is still empty does nothing and says
    /// nothing, so this is how a caller asks whether the claim it made is the
    /// one a key will follow. See `focusLast`.
    fn hasFocus(self: Surface) bool {
        return switch (self) {
            .terminal => |one| one.focus_mgr.current != null,
            .window => |one| one.focus_mgr.current != null,
        };
    }
};

/// One running display, and the observer that feeds it.
///
/// Built at a stable address by `start`, because a `phantom.tui.Session` holds
/// pointers into its own fields and `Frames`'s writer is one of them.
pub const Ui = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// The observer this one wraps, once `wrap` has been told which. Null until
    /// then, because the display comes up before there is a session to watch:
    /// the message is typed in it first.
    inner: ?chock_core.Loop.Observer = null,
    /// Every byte `src/run.zig`'s `Printer` wrote this session, and every
    /// diagnostic written while the display was up. **Owned here**, so the
    /// display can show its tail while the session runs and write the whole of
    /// it back to the real screen when it gives the display up.
    ///
    /// **The diagnostics are in it because standard error reaches no terminal
    /// while a display holds one.** See `Diagnostics`. A run with no display
    /// leaves them in the same scrollback by the ordinary route, so what a
    /// person can read afterwards is the same either way.
    transcript: std.ArrayList(u8) = .empty,

    /// What the display is showing. See `askForMessage`.
    phase: Phase = .message,
    /// What has been typed into the field. Filled by `TextField.on_change`,
    /// which hands over a borrowed slice, so this is a copy.
    typed: std.ArrayList(u8) = .empty,
    /// Set by the message field's own key listener when Enter is pressed.
    submitted: bool = false,
    /// A message the caller already had, for the first turn. Borrowed, and
    /// handed over once: see `prime`.
    primed: ?[]const u8 = null,

    /// How many rows above the newest the transcript is showing. Zero is the
    /// bottom, which is where a session sits until somebody scrolls.
    scroll_back: usize = 0,
    /// Which row of the completion list is chosen. See `openCompletions`.
    completion_selected: usize = 0,

    /// The sessions `/resume` is offering, and which is chosen. Null when the
    /// picker is not open. Every string in it is owned by `arena`.
    picker: ?[]const Resumable = null,
    picked: usize = 0,
    /// Where this project keeps its session logs, and which one is this. Both
    /// borrowed from `src/run.zig`'s arena: see `resumable`.
    sessions_dir: []const u8 = "",
    current_session: []const u8 = "",
    /// The session a person chose. `src/run.zig` reads it after the loop ends.
    taken: ?[]const u8 = null,

    /// What the session has spent so far, folded from `usage` events. The
    /// currency is empty until one arrives that names a cost, which is what
    /// `/usage` reads as "not known": see `chock_proto.event.Cost`.
    tokens_in: u64 = 0,
    tokens_out: u64 = 0,
    spent: f64 = 0,
    spent_currency: []const u8 = "",

    /// Whether the transcript region holds the keyboard focus. Kept here as
    /// well as in phantom's focus manager because the band draws itself
    /// differently when it does. Focus is a security surface, and therefore
    /// something that has to be visible.
    transcript_focused: bool = false,

    /// The question on screen, or null when there is none. **Absent is the
    /// design**: the region is gone until a request arrives, so that its
    /// arrival is itself a signal. Every string in it belongs to
    /// `approval_arena`.
    approval: ?Approval = null,
    /// Whether the approval region holds the keyboard focus. It takes it on
    /// arrival and keeps it while the question is open: see `awaitAnswer`.
    approval_focused: bool = false,
    /// Looks left before a key can answer. See `settle_looks`.
    approval_settle: u8 = 0,
    /// What the person said, set by the region's own key listener and taken by
    /// `awaitAnswer`.
    approval_answer: ?Answered = null,
    /// Owns every string of `approval`. **Reset for each question**, because a
    /// `detail` is a whole diff and a session may answer many.
    approval_arena: std.heap.ArenaAllocator,

    /// The question the agent asked, or null when there is none. **Absent is
    /// the design**, the same rule `approval` follows: the region's arrival is
    /// itself the signal. Every string in it belongs to `question_arena`.
    ///
    /// **Never open at the same time as `approval`.** A turn asks for one thing
    /// at a time and each holds the session until it is answered, and the two
    /// regions share the rows `split` gives the raised panel: see `panelRows`.
    question: ?Question = null,
    /// Whether the question region holds the keyboard focus.
    question_focused: bool = false,
    /// Looks left before a key can answer. See `settle_looks`.
    question_settle: u8 = 0,
    /// What the person has typed into the answer line, and how much of it there
    /// is.
    ///
    /// **A fixed buffer and not a list**, the same shape `chock_core.ask.Prompt`
    /// keeps: the bound is a contract of that file and not a matter of memory,
    /// so an answer longer than `max_answer_bytes` is refused a byte at a time
    /// at the keyboard rather than allocated and cut afterwards.
    question_typed: [chock_core.ask.max_answer_bytes]u8 = undefined,
    question_filled: usize = 0,
    /// How the person finished, set by the region's own key listener and taken
    /// by `awaitText`.
    question_said: ?enum { answered, declined } = null,
    /// Owns every string of `question`. Reset for each question.
    question_arena: std.heap.ArenaAllocator,
    /// How a Ctrl-C read as a key is turned back into the signal it would have
    /// been. **A seam, and the only reason it is one is the order**: the device
    /// has to be out of raw mode before this runs, or a second press ends the
    /// process with the terminal still raw. A test watches that order here,
    /// because the real call ends the test binary on a second press. See
    /// `awaitAnswer`.
    raise: *const fn (std.posix.SIG) std.posix.RaiseError!void = std.posix.raise,

    /// How the terminal's own settings are written. **A seam, and the only
    /// reason it is one is that a test binary has no terminal**: `/dev/null`
    /// refuses `tcsetattr`, so which bits a turn really runs with could not be
    /// read back at all. A real display gets the operating system's own call.
    /// See `quietOf`, which is what decides those bits.
    apply_termios: *const fn (
        std.posix.fd_t,
        std.posix.TCSA,
        std.posix.termios,
    ) std.posix.TermiosSetError!void = std.posix.tcsetattr,

    /// The transcript as rows, each one knowing whose voice it is in. Owned
    /// here, oldest dropped once there are `kept_lines` of them.
    lines: std.ArrayList(Line) = .empty,
    /// The row being written, before its newline arrived. Streaming delivers
    /// the model's answer a few characters at a time, so most rows are built
    /// here first.
    pending: std.ArrayList(u8) = .empty,
    /// Whose voice `pending` is in.
    pending_voice: Voice = .chock,

    /// Which row of `lines` the transcript's own focus is on, or null when it
    /// is on none.
    ///
    /// **Focus reaches a row and not only a region**, since `Space` expands the
    /// focused thing: a tool result, a reasoning block, a compaction, or a
    /// subagent. Every one of those is a row with a `Fold`, and this is the row
    /// that has it. See `onTranscriptKey`.
    cursor: ?usize = null,

    /// The pane over the transcript, or none.
    ///
    /// **A pane, and it has to be a pane.** `?` shows every key in a pane, and
    /// a pane is a thing a person can read all of. Rows written into the
    /// transcript are not that: on a short screen the end of a long answer is
    /// off the bottom the moment it is written, and it also leaves the keys in
    /// the session's own record, which the transcript is.
    ///
    /// **Over the transcript, and over nothing else.** It is drawn inside the
    /// transcript region, so the header, the approval region and the input line
    /// all stay where they are and an approval that arrives while the pane is
    /// open is still visible. The approval region has a keyboard and a surface
    /// of its own, and a pane that covered it would take both.
    pane: ?Pane = null,

    /// Whether the plan sidebar is wanted beside the transcript.
    ///
    /// **Wanted, and not drawn.** A window narrower than
    /// `sidebar_needs_columns` has no room for two columns, so the sidebar is
    /// not built at all there and the transcript keeps the whole width. This
    /// flag is what brings it back when the window grows again: see
    /// `sidebarWidth`.
    ///
    /// **What is folded and never a second copy of it.** The rows come from
    /// `plan`, which is the same fold `plan.update` writes and `replay`
    /// rebuilds, so a resumed session's sidebar and its log cannot disagree.
    sidebar_open: bool = false,

    /// Whether the caller stated the display geometry rather than leaving it to
    /// the device. True for a test and false for every real run. See
    /// `followSize`, which must not ask a device that has no size to give.
    fixed_size: bool = false,

    /// The tool call that has not come back yet. Null when none is running.
    /// **Owned here**, because the event it was read from is borrowed for the
    /// call that delivered it and the answer arrives much later.
    running_call: ?Running = null,
    /// Which row of `lines` that call is drawn on, so the same row carries the
    /// outcome and the duration when it comes back. Null once the oldest rows
    /// have been dropped past it.
    running_row: ?usize = null,

    /// The model's reasoning for the turn being spoken, as it arrives. Folded
    /// into one row the moment the model says anything else: see
    /// `foldReasoning`.
    ///
    /// **Kept and never dropped.** Reasoning is never hidden with no trace,
    /// because it is part of the turn.
    reasoning: std.ArrayList(u8) = .empty,
    /// Whether this turn already has its header row. See `openTurn`.
    turn_open: bool = false,

    /// What time it is, and how far this machine's zone is from UTC.
    ///
    /// **A seam, so a row that shows a time is a row a test can read.** Every
    /// real caller gets the machine's own clock, set in `start`. A test states
    /// one, which is what keeps a duration and a turn's clock time out of the
    /// suite's assertions about wall time.
    ///
    /// **The default says nothing rather than guessing.** It is replaced in
    /// `start`, which is the one place that has the `std.Io` a real clock is
    /// read through.
    clock: chock_core.notices.Clock = .{ .nowMs = noClock },

    surface: Surface,
    frames: Frames = .{},
    /// Where a warning goes while this display is up. Installed by `start` and
    /// put back by `stop`. See `Diagnostics`.
    diagnostics: Diagnostics = .{},

    /// True while a log is being folded back in. **A replay draws no frame**:
    /// see `replay` and `draw`.
    replaying: bool = false,

    /// How much room the display has: rows of text, and how wide one is.
    ///
    /// **Measured from what phantom laid out, on every frame.** `Ui.resize` is
    /// the only writer and `Ui.view` is where it runs. A row is the unit down
    /// the screen because a character grid draws one row per cell and a pixel
    /// run draws a real font whose line box is taller than a cell, so the same
    /// terminal holds a different number of each. Across the screen there is no
    /// unit at all: a width and the face to measure it with is the whole
    /// answer. See `Measure` and `Room`.
    ///
    /// **Nothing until the first build**, which phantom runs while the display
    /// is still starting, so nothing outside this file can read a frame drawn
    /// from them before they are measured. A width of zero draws no words, and
    /// the grid measure is what a display that has measured nothing has.
    rows: u16 = 0,
    width: f32 = 0,
    measure: Measure = grid_measure,

    /// Owns every string in `plan`. Never reset: a plan is at most a few
    /// hundred short steps over a whole session.
    arena: std.heap.ArenaAllocator,
    plan: chock_proto.state.Plan = .{},

    /// What the header band says. Filled by `describe`, which `src/run.zig`
    /// calls once. Empty until then, and a header of empty facts is still a
    /// header: it is the band and the surface that mark the region.
    facts: Facts = .{},

    /// How many lines had gone past the display when it last painted every
    /// cell. See `src/tty.zig`'s `scrolled`.
    seen_scrolls: u32 = 0,
    /// False once the session has stopped, after which no frame is drawn.
    running: bool = true,
    /// Whether the transcript already carries the line that says a stop was
    /// asked for. See `noteStopping`.
    said_stopping: bool = false,
    /// Whether the display has been given back. See `stop`.
    stopped: bool = false,
    /// The keyboard, when Chock is the one holding it. Null otherwise. See
    /// `Keys`.
    keys: ?Keys = null,
    /// The mounted state, so a new frame can be asked for. Filled by
    /// `Screen.State.initState` during `Session.init`.
    screen: ?*Screen.State = null,

    /// The most of a notice the status row keeps. A notice is one sentence by
    /// contract, and a row is one screen wide, so this is already more than a
    /// row can show.
    const status_bytes = 256;

    /// What the display is for at this moment.
    ///
    /// **Two, and they never overlap.** While the message is being typed the
    /// terminal is read; once a turn starts it is not read again, and the field
    /// is gone until the turn comes back. See `askForMessage`.
    pub const Phase = enum { message, session };

    /// The keyboard, when Chock is the one holding it.
    ///
    /// **This says what Chock configured, and nothing about what a backend can
    /// do.** `terminalOptions` leaves `input` at phantom's `.fed` default so
    /// that the device is read in one place, for one phase at a time, under raw
    /// mode this file turns on and off. A display Chock handed no device to has
    /// nothing here, and phantom delivers those keys itself.
    ///
    /// **One `Term` for the whole run, and not a fresh one per turn.** The
    /// device is what a read goes to and what the settings below belong to, and
    /// a second copy of it would carry a second answer to both.
    ///
    /// **The settings are Chock's, and not phantom's.** `Term.enterRaw` saves
    /// what the terminal had and `Term.leaveRaw` puts all of it back at once,
    /// which is two states. The display needs three: raw while it reads the
    /// keyboard, the person's own settings with no echo while a turn runs, and
    /// the person's own settings exactly at the end. So `start` moves what
    /// phantom saved into `was`, clears phantom's copy, and this file is the one
    /// thing that writes them from then on. See `quietOf`.
    const Keys = struct {
        /// The device Chock reads and puts in raw mode.
        device: phantom.tui.term.Term,
        /// Where the bytes it reads go.
        session: *phantom.tui.Session,
        /// Whether the device is in raw mode now.
        raw: bool,
        /// What the terminal had before Chock touched it, or null when the
        /// device would not take raw mode at all. `dropKeys` writes it back.
        was: ?std.posix.termios = null,
        /// What raw mode is on this machine: the settings `Term.enterRaw` chose,
        /// **read back from the device** rather than written out a second time
        /// here, so a copy of phantom's own list of bits cannot drift from it.
        /// Null with `was`.
        held: ?std.posix.termios = null,
    };

    /// One tool call that has been asked for and has not answered.
    ///
    /// **`chock_proto.event.ToolResult` carries no duration**, and a person
    /// reading a transcript wants one, so the display measures the gap itself
    /// between the two events it is told about. See `Ui.clock`.
    const Running = struct {
        /// The tool's name, and its argument as a person reads it. Both owned
        /// by the `Ui`, and freed when the call comes back.
        tool: []const u8,
        argument: []const u8,
        /// When the call was asked for, by `Ui.clock`.
        at_ms: i64,
    };

    /// What the clock says before `start` has given the display a real one.
    fn noClock(ctx: ?*anyopaque) i64 {
        _ = ctx;
        return 0;
    }

    /// The machine's own real time, in milliseconds since the epoch.
    fn realNowMs(ctx: ?*anyopaque) i64 {
        const self: *const Ui = @ptrCast(@alignCast(ctx.?));
        return std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    }

    /// Take the display, with nothing to show on it yet.
    ///
    /// **The message is typed before there is a session**, so nothing about a
    /// session is passed in here. `wrap` is what connects one afterwards.
    ///
    /// On any error nothing has been taken. That is why this returns an error
    /// rather than reporting one: what a caller does about a terminal that will
    /// not give its size is the caller's decision.
    pub fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        environ: *const std.process.Environ.Map,
        attach: Attach,
    ) !*Ui {
        const self = try gpa.create(Ui);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .io = io,
            // Filled below, once the session that decides them exists. A
            // `Session` holds pointers into its own fields, so it is built in
            // place at an address that does not move.
            .surface = undefined,
            .rows = 0,
            .width = 0,
            .measure = grid_measure,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .approval_arena = std.heap.ArenaAllocator.init(gpa),
            .question_arena = std.heap.ArenaAllocator.init(gpa),
            .seen_scrolls = tty.scrollCount(),
        };
        errdefer self.arena.deinit();
        errdefer self.approval_arena.deinit();
        errdefer self.question_arena.deinit();

        // **The machine's own clock, and the machine's own zone.** A turn's
        // header states a local time, and `src/clock.zig` is where the offset
        // is read from the operating system's database rather than guessed. A
        // zone that cannot be read is UTC, which is the honest answer.
        const at = std.Io.Timestamp.now(io, .real).toMilliseconds();
        self.clock = .{
            .ctx = self,
            .nowMs = realNowMs,
            .utc_offset_minutes = clock_mod.localOffsetMinutes(gpa, io, at),
        };

        switch (attach) {
            .terminal => |terminal| {
                // **Asked before the session is built, and then given to it.**
                // The tree is mounted inside `init`, and the first frame it
                // builds needs to know how much room there is; a size read
                // afterwards would make that frame the one wrong one. Passing
                // the same value on means the two cannot disagree.
                var device = phantom.tui.term.Term.initFiles(io, terminal.in, terminal.out);
                const size = terminal.size orelse try device.size();
                // **A stated size is the caller's to change and nobody else's.**
                // See `followSize`, which asks the device every frame and must
                // not ask one that was never the source of the answer.
                self.fixed_size = terminal.size != null;

                // **Raw mode goes on here, before the session is built, and
                // comes off in `endInput`.** That span is wider than
                // `Options.raw_mode` can express and both ends of it need it:
                // the capability probe inside `init` reads the terminal's reply
                // itself, and a terminal that is not raw answers a read only
                // when the person presses return; and the message is typed
                // straight after, which needs keys one at a time. See
                // `askForMessage` for why it comes off the moment the message
                // is in.
                //
                // A device that will not take raw mode still draws. It answers
                // no probe and takes no key.
                //
                // **The probe reads the terminal, so it eats what is typed
                // while it runs.** A terminal answers the DA1 query in
                // milliseconds and `Session.init` stops reading the moment the
                // answer arrives, so a person cannot type inside that window.
                // A device that never answers costs the probe its whole budget
                // instead, about three seconds, and anything typed then is
                // swallowed with the reply that never came. That is the price
                // of letting phantom pick its own drawing mode, and it is paid
                // by fake terminals rather than real ones.
                //
                // **The settings move here and phantom's copy is cleared.**
                // Phantom puts every bit back at once and the display needs a
                // third state between raw and the person's own: see `Keys` and
                // `quietOf`. `enterRaw` still does the work, because it also
                // installs the resize handler, and what it chose is read back
                // rather than written out a second time here.
                //
                // **Asked whether the device is a terminal first**, and
                // measured on Darwin. `tcgetattr` on something that is not one
                // answers `ENOTTY` on Linux, which Zig knows and turns into an
                // error `enterRaw` reports; on Darwin `/dev/null` answers
                // `ENODEV`, which Zig does not know, so `unexpectedErrno` dumps
                // a stack trace on standard error before returning. A caught
                // error cannot undo bytes that are already written, and a build
                // log with a trace in it reads exactly like a suite that broke.
                // A device that is not a terminal has no raw mode to enter
                // either way, so asking is not only cheaper, it is the honest
                // question.
                var was: ?std.posix.termios = null;
                var held: ?std.posix.termios = null;
                if (terminal.in.isTty(io) catch false) device.enterRaw() catch {};
                if (device.saved) |original| {
                    device.saved = null;
                    if (std.posix.tcgetattr(terminal.in.handle)) |now| {
                        was = original;
                        held = now;
                    } else |_| {
                        // Nothing can be read back, so nothing can be put on
                        // again turn after turn. The terminal goes back as it
                        // was and the run takes no key, which is the same
                        // outcome as a device that refused raw mode.
                        putTermios(terminal.in.handle, original);
                    }
                }
                const raw = was != null;
                errdefer if (was) |original| putTermios(terminal.in.handle, original);

                const session = try gpa.create(phantom.tui.Session);
                errdefer gpa.destroy(session);
                // **The terminal's own grid is not read here.** A cell count is
                // the right answer for the character grid backend and the wrong
                // one for the pixel backend, and which of the two is in use is
                // phantom's decision and is made inside `init` below. The first
                // build measures instead: see `Ui.resize`.
                var options = terminalOptions(self, terminal);
                options.size = size;
                // Only when there is a terminal in raw mode to answer it. See
                // above: the probe reads its own reply.
                options.query_capabilities = raw;
                // `Session.init` unwinds everything it did on an error, and a
                // caller that gets one must not call `deinit`. See its own doc
                // comment.
                try session.init(
                    gpa,
                    io,
                    environ,
                    phantom.Root.of(Ui, rootOf, self),
                    options,
                );
                self.surface = .{ .terminal = session };
                // The device travels here with the settings it was found in and
                // the settings raw mode is, and every turn goes through this one
                // copy of both from now on. See `Keys`.
                self.keys = .{
                    .device = device,
                    .session = session,
                    .raw = raw,
                    .was = was,
                    .held = held,
                };
                self.sayProbe(session.caps, session.mode, raw);

                // Only now is there a screen to put back, so only now may a
                // second Ctrl-C write the sequences that put it back. **The
                // terminal alone**: a window leaves no terminal setting behind
                // it, so there is nothing for a handler to undo.
                interrupt.armTerminalRestore();
                // **And the settings, from the same press.** A turn runs with
                // the echo off, and a process that ended there would leave a
                // shell that shows nothing a person types.
                if (was) |original| interrupt.armTerminalSettings(terminal.in.handle, original);
            },
            .window => |window| {
                // **Nothing is guessed here.** A window reports pixels and
                // nothing else, and how many rows of text those pixels hold is
                // a question only a measured line box answers. `Ui.resize`
                // asks it on the first build, which phantom runs inside `init`
                // below and after it has opened the view these numbers come
                // from. See `Measure`.
                const session = try gpa.create(phantom.window.Session);
                errdefer gpa.destroy(session);
                try session.init(
                    gpa,
                    io,
                    environ,
                    phantom.Root.of(Ui, rootOf, self),
                    windowOptions(window),
                );
                self.surface = .{ .window = session };
            },
        }

        // **From here on a warning is a row and not a line on a screen that is
        // repainted.** Installed last, so everything above still reaches the
        // real terminal: `start` can fail, and a diagnostic about a display
        // that never opened belongs where a person is already looking.
        //
        // **Both backends.** A window is what the person is watching, so a
        // warning that stayed in the terminal behind it would be a warning
        // nobody reads, and `stop` writes the transcript back into that
        // terminal for a window run too.
        self.diagnostics.ui = self;
        self.diagnostics.was = tty.useErrStream(io, &self.diagnostics.writer);

        return self;
    }

    /// Everything phantom's terminal backend is told. A function and not a
    /// literal at the call site, so a test can read the answer without a
    /// terminal: see the tests below, which pin the fields that decide who owns
    /// Ctrl-C.
    pub fn terminalOptions(self: *Ui, attach: Attach.Terminal) phantom.tui.Options {
        return .{
            // The real standard input, and the message really is typed on it.
            // **Phantom is not the reader**: `input` follows `raw_mode`, which
            // is false below, so it defaults to `.fed`, and `askForMessage` is
            // the one reader, for one phase. See this file's own top comment.
            .in = attach.in,
            .out = attach.out,
            // Every byte through `src/tty.zig`, so a frame cannot overtake a
            // warning or a row.
            .writer = &self.frames.writer,
            .size = attach.size,
            // **False because Chock has already done it**, and holds it for
            // longer than a session can: `start` turns raw mode on before this
            // session is built, and `takeKeys` and `giveKeys` are the only
            // things that turn it on and off from then on. Outside the two
            // spans they mark, `ISIG` is back and `src/interrupt.zig` owns
            // Ctrl-C, which is what lets a second press reach a running tool
            // call. `start` overrides `query_capabilities` to match.
            .raw_mode = false,
            .install_signal_handlers = false,
            // Chock installs its own panic behaviour and its own handlers.
            .install_panic_hook = false,
            // Chock owns its standard error and says where a warning goes. A
            // redirect here would take the program's diagnostics away from the
            // stream `src/tty.zig` promises they are on.
            //
            // **This is why a warning needed somewhere else to go.** Left
            // alone, the descriptor points at the real terminal for the whole
            // session, so a line written to it landed on the alternate screen
            // and the next frame painted over it. `Diagnostics` is the answer,
            // and it moves the writer rather than the descriptor.
            .stderr = .leave,
            // The alternate screen, so the terminal a person had is still there
            // when the session ends. `stop` writes the transcript back out on
            // to it.
            .own_screen = true,
            // **`NO_COLOR` says no colour, not no interface.** So a person who
            // set it, or typed `--color=never`, gets the display drawn in the
            // colours the terminal already holds and not one SGR byte.
            // `src/tty.zig`'s painter is that whole answer, already decided.
            .color = if (tty.stdoutPainter().on) null else .none,
        };
    }

    /// Everything phantom's window backend is told.
    ///
    /// **Nothing about the terminal appears here**, and that is the shape of the
    /// difference: a window has no alternate screen to take, no `TERM` to
    /// believe, no raw mode, and no stream to share with anything else. What is
    /// left is a size and a title.
    pub fn windowOptions(attach: Attach.Window) phantom.window.Options {
        return .{
            .title = "chock",
            .width = attach.width,
            .height = attach.height,
            // **Zero, and never the default.** `poll_ms` is how long `step`
            // waits for an event before it returns, and every `step` here runs
            // inside an observer call on the one thread that also runs the
            // session. A frame's worth of waiting on every word the model says
            // would slow the session down to the display's own frame rate.
            .poll_ms = 0,
        };
    }

    /// Take the message, typed into the display.
    ///
    /// **The stream Chock owns is read here and nowhere else, ever.** See
    /// `keyboard` for which stream that is and why Chock reads it at all. Raw
    /// mode goes on for exactly as long as this runs, because that is what makes
    /// a key arrive one at a time: `enterRaw` sets `VMIN 0` and `VTIME 1`, so the
    /// read below returns within a tenth of a second whether or not something
    /// was typed and the loop keeps drawing. It goes off again on every path out.
    ///
    /// **Raw mode also turns `ISIG` off, and that is why it is only on here.**
    /// With it off, Ctrl-C is an ordinary key rather than a signal, and phantom
    /// catches it before the tree and stops. That is the right answer for a
    /// person who changed their mind before anything ran. It would be the wrong
    /// answer once a session is running, where the second press has to reach
    /// `chock_core.tools.cancelRunningTool` during a tool call and no `step`
    /// runs then. So the moment the message is in, raw mode is off and
    /// `src/interrupt.zig` owns Ctrl-C for the rest of the run.
    ///
    /// **Called once for every turn**, not once for the session. Raw mode goes
    /// on at the top and off at the bottom each time, so between two turns there
    /// is exactly one owner of Ctrl-C at every moment: phantom while the field
    /// is up and `ISIG` is off, `src/interrupt.zig` the rest of the time.
    ///
    /// Null is the person saying they are done: an empty message, Ctrl-C at the
    /// field, or a display that stopped. `src/run.zig` reads it as the end of
    /// the session, which is written to the log the same way every other ending
    /// is.
    pub fn askForMessage(self: *Ui, arena: std.mem.Allocator) !Ask {
        // On every path out, including an error and the primed message below: a
        // display that held the keyboard through a turn would hold `ISIG` off
        // through it, and `src/interrupt.zig` could not own Ctrl-C.
        defer self.endInput();

        // A message that was already on standard input is this turn's, and it
        // is used once. The field never comes up for it, so nothing flickers.
        // **It is said in the transcript all the same**, because a piped message
        // is still the person's half of the conversation: see `saidByUser`.
        if (self.primed) |message| {
            self.primed = null;
            self.saidByUser(message);
            return .{ .message = try arena.dupe(u8, message) };
        }

        // One turn of this asks for one line. A line that turns out to be a
        // command is answered and the field opens again, which is the `continue`
        // at the bottom.
        while (true) {
            self.beginInput();

            while (!self.submitted) {
                // False here is the display saying stop: Ctrl-C at the field, or a
                // window closed. Nothing was asked for, so nothing runs.
                //
                // **The one look this loop makes has to wait**, because the read
                // below is what bounds it and a window has no device to read.
                // Without this the loop drew a frame and asked for the next one
                // with no wait at all: measured on weston, a window sitting at
                // the field spent 99 percent of a core doing that. See
                // `Surface.stepWaiting`, and `look_ms` for the number.
                if (!self.paintWaiting(look_ms)) return .done;

                // After the first frame, because the traversal order is rebuilt from
                // the tree and there is no tree to walk until one has been built.
                //
                // **Asked on every turn until it takes, and not once after the
                // first frame.** A terminal draws on every `step`, so one frame
                // is always enough there. A window draws only when the
                // compositor grants a frame, so the first turns build no tree,
                // and a claim made once against an empty order was a claim
                // dropped for the whole session: a person then had to press
                // `Tab` before one letter of theirs arrived. This is the same
                // shape `awaitAnswer` and `awaitText` already keep for their own
                // regions. See `Surface.focusLast`.
                if (!self.surface.hasFocus()) self.surface.focusLast();

                if (self.keys) |*keys| {
                    var buffer: [read_bytes]u8 = undefined;
                    const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                        // **Nothing arrived, and that is not the end of anything.**
                        // Raw mode's `VMIN 0` and `VTIME 1` make a read with no key
                        // waiting come back empty after a tenth of a second, and an
                        // empty read on a file is how a stream says it ended. So a
                        // person who has not typed yet reads as end of stream, every
                        // tenth of a second, for as long as they are thinking.
                        // Phantom's own `readIdle` answers this the same way.
                        error.EndOfStream => 0,
                        else => |e| return e,
                    };
                    if (read > 0) keys.session.feed(buffer[0..read]);
                }
            }

            // **A command is answered here and never returned.** Nothing of it
            // becomes a user message, so nothing of it reaches the log, an
            // event, or the model: see `answerFor`, which is the whole of that
            // decision and is where a test can reach it.
            //
            // **A loop and not a call to itself**, because a person may run
            // twenty commands before they type a message and Zig promises no
            // tail call.
            // **A session was chosen from the picker**, which is not a line at
            // all: `takePicked` set it and submitted for the person. See `Ask`.
            if (self.taken) |id| {
                self.taken = null;
                return .{ .take_up = try arena.dupe(u8, id) };
            }

            switch (answerFor(self.typed.items)) {
                .nothing => return .done,
                .message => |words| {
                    // Before the copy, so a transcript holds what was sent even
                    // if the copy is what fails. See `saidByUser`.
                    self.saidByUser(words);
                    return .{ .message = try arena.dupe(u8, words) };
                },
                .command => |command| {
                    self.runCommand(command);
                    // **One frame with no field.** A `phantom.TextField` owns
                    // its text after it is mounted and a rebuild deliberately
                    // does not take it again, so without a frame that leaves the
                    // field out, the next turn would open with the command still
                    // in it. Taking it out unmounts it, and the frame after this
                    // one mounts a fresh, empty one.
                    self.phase = .session;
                    _ = self.paint();
                    continue;
                },
            }
        }
    }

    /// The word a person's own rows are headed with.
    ///
    /// **The design's own word for the person.** The spawn chain is written as
    /// `you \u{25b8} glm4.7-flash \u{25b8} reviewer`, so a transcript and an
    /// approval name them the same way.
    const said_by_user = "you";

    /// Put what the person said into the transcript.
    ///
    /// **Chock's voice, at column 0, under the rail.** It did not come from the
    /// model, and `Voice` makes that structural rather than a matter of styling:
    /// agent content is indented past the rail and never carries one. Without
    /// this the scrollback held turn headers, reasoning, tool calls and answers
    /// and nothing the person typed, so it could not be read as a conversation,
    /// which is most of what a transcript is for.
    ///
    /// **A header row and then the words**, which is the shape every other
    /// block has: a name at the left and the clock at the right, on the row
    /// that opens the block. The time column is one the eye can ignore, and a
    /// second shape in it would be one to read.
    ///
    /// **Every path that sends a message comes through here**: the field, and a
    /// message that was already on standard input.
    fn saidByUser(self: *Ui, text: []const u8) void {
        // A block of its own, so a message a person sent is separated from the
        // turn before it. See `startBlock`.
        self.startBlock();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // **The clock is carried on the row and laid out every frame.** The
        // room it is pinned in is the transcript's and not the screen's: the
        // transcript stops at a readable measure and the plan sidebar takes
        // width off it again. A row that was padded out to the width it was
        // built at kept a clock the next narrower window wrapped away. See
        // `Line.pinned`.
        const at = clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch "";
        self.sayPinned(.chock, said_by_user, at);

        self.say(.chock, text);
        self.endLine();
        self.draw();
    }

    /// Answer a command, in Chock's own voice, in the transcript.
    ///
    /// **Every answer is a Chock row.** A command is the harness talking to the
    /// person, so it carries the rail and sits at column 0, exactly as every
    /// other thing Chock says does. See `Voice`.
    fn runCommand(self: *Ui, command: Command) void {
        switch (command) {
            .help => self.openHelp(),
            .plan => self.togglePlan(),
            .usage => self.sayUsage(),
            .@"resume" => self.openPicker(),
        }
    }

    /// Show every key and every command, in a pane over the transcript.
    ///
    /// **`/help` and `?` are the same act**, so neither can show something the
    /// other does not. See `Pane`, and `helpRows` for what is in it.
    ///
    /// **Opening it again puts it back at the top**, which is what a person
    /// asking for it a second time wants: they are looking for something, not
    /// carrying on from where they stopped.
    fn openHelp(self: *Ui) void {
        self.pane = .{ .kind = .keys };
    }

    /// Every key and every command, as the rows of the help pane.
    ///
    /// **The pane's own keys are in it**, because a person who cannot close a
    /// pane is stuck in it, and a person who cannot see that it scrolls reads
    /// the first screen and believes that is all there is.
    ///
    /// **The commands are read from `Command`** rather than written a second
    /// time here, so a command that is added is in the pane without anybody
    /// remembering to put it there.
    fn helpRows(
        arena: std.mem.Allocator,
    ) std.mem.Allocator.Error![]const []const u8 {
        var rows: std.ArrayList([]const u8) = .empty;
        try rows.append(arena, "keys");
        for ([_][2][]const u8{
            .{ "Enter", "send what you typed" },
            .{ "Ctrl-C", "once stops the turn, twice leaves" },
            .{ "Tab", "move the focus between the transcript and the input" },
            .{ "up down", "scroll the transcript, and step between the rows that open" },
            .{ "Space", "open or close the focused row, with the transcript focused" },
            .{ "g", "go to the newest row, with the transcript focused" },
            .{ "p", "open the plan beside the transcript, or close it" },
            .{ "?", "this" },
        }) |pair| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                pair[0],
                pair[1],
            }));
        }

        try rows.append(arena, "");
        try rows.append(arena, "in this pane");
        for ([_][2][]const u8{
            .{ "up down", "read the rest of it" },
            .{ "Esc", "close it" },
            .{ "?", "close it" },
        }) |pair| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                pair[0],
                pair[1],
            }));
        }

        try rows.append(arena, "");
        try rows.append(arena, "commands");
        for (Command.all) |one| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                one.typed(),
                one.does(),
            }));
        }
        try rows.append(arena, "");
        // The rule that keeps a path a path. See `commandOf`.
        try rows.append(arena, "a line whose first word is not one of those is a message");
        return rows.items;
    }

    fn sayPlan(self: *Ui) void {
        if (self.plan.isEmpty()) {
            self.sayFmt(.chock, "the agent has written no plan", .{});
            return;
        }
        const counts = self.plan.counts();
        self.sayFmt(.chock, "plan: {d} done, {d} left", .{ counts.done, counts.left() });
        for (self.plan.steps.items) |step| {
            self.sayFmt(.chock, "  {s: <12} {s}", .{ step.status.wireName(), step.subject });
        }
    }

    /// Open the plan sidebar, or close it.
    ///
    /// **`/plan` and `p` are the same act**, which is the rule `openHelp`
    /// already sets for `/help` and `?`. Neither can show something the other
    /// does not.
    ///
    /// **A display too narrow for two columns is told so and given the plan
    /// anyway**, in the transcript, which is where `/plan` always wrote it. A
    /// refusal that left a person with no way to read the plan would be worse
    /// than the crowded layout it avoids. See `sidebar_needs_columns`.
    fn togglePlan(self: *Ui) void {
        if (self.sidebar_open) {
            self.sidebar_open = false;
            return;
        }
        if (!self.fitsSidebar()) {
            self.sayFmt(
                .chock,
                "there is no room beside the transcript. A wider display keeps the plan there.",
                .{},
            );
            self.sayPlan();
            return;
        }
        self.sidebar_open = true;
    }

    /// Fold one `plan.update` in, and say what a person needs to read about it.
    ///
    /// **A list of N steps used to cost N rows every time any one of them
    /// moved.** One `update_plan` call really did write four rows saying what
    /// each step is now, and the transcript is not the place for a thing that
    /// has one current state. With the sidebar open the standing state is
    /// beside the transcript, so one row is enough: how much is done, and what
    /// is being worked on.
    ///
    /// **A step that was given up keeps a row of its own, open sidebar or
    /// not.** That is an event and not a state: the sidebar says a step is
    /// stopped now, and only the transcript can say when it stopped and what
    /// else was happening. `chock_proto.event.PlanStatus` makes the same point
    /// for the log, that `abandoned` is not `done` and not an omission.
    ///
    /// **With the sidebar closed nothing collapses.** The transcript is then
    /// the only place the plan is, so every step of the update keeps its row.
    fn foldPlan(self: *Ui, update: chock_proto.event.PlanUpdate) void {
        // Which steps are newly given up has to be read before the fold, because
        // afterwards an update that repeats a status it already had looks the
        // same as one that changed it.
        var gave_up: [max_said_steps]usize = undefined;
        var count: usize = 0;
        for (update.steps, 0..) |step, at| {
            if (!isStatus(step.status, .abandoned)) continue;
            if (self.plan.find(step.id)) |had| {
                if (isStatus(had.status, .abandoned)) continue;
            }
            if (count == gave_up.len) break;
            gave_up[count] = at;
            count += 1;
        }

        // A plan that could not be folded is left as it was. An observer
        // watches and never decides: an allocator that has refused is not this
        // file's fault to report.
        self.plan.apply(self.arena.allocator(), update) catch {};

        if (!self.sidebar_open) {
            for (update.steps) |step| {
                self.sayFmt(.chock, "plan step {s} is now {s}", .{
                    step.id,
                    step.status.wireName(),
                });
            }
            return;
        }

        for (gave_up[0..count]) |at| {
            self.sayFmt(.chock, "plan step {s} was given up: {s}", .{
                update.steps[at].id,
                update.steps[at].subject,
            });
        }

        const counts = self.plan.counts();
        const now = self.stepInProgress();
        if (now) |one| {
            self.sayFmt(.chock, "plan: {d} of {d} done, now on \"{s}\"", .{
                counts.done,
                counts.total(),
                one.subject,
            });
        } else {
            self.sayFmt(.chock, "plan: {d} of {d} done", .{ counts.done, counts.total() });
        }
    }

    /// The most steps of one update that can each get a row of their own. An
    /// update is a whole task list, which `chock_core.tools` already bounds.
    const max_said_steps = 64;

    /// The first step being worked on, or null when none is.
    fn stepInProgress(self: *const Ui) ?chock_proto.state.Plan.Step {
        for (self.plan.steps.items) |step| {
            if (isStatus(step.status, .in_progress)) return step;
        }
        return null;
    }

    /// Say what the terminal answered when it was asked what it can do.
    ///
    /// **A capability probe whose answer nobody can see fails silently for
    /// ever.** This is the one place the answer exists, so it is written down
    /// here, under `--verbose`, and it is the whole of what Chock can see.
    ///
    /// **Into the transcript and not to standard error.** By the time the
    /// answer exists the alternate screen has been taken, three lines above it
    /// in `phantom.tui.Session.init`, so a diagnostic written to the terminal
    /// would land on a screen the next frame throws away. The transcript is
    /// where Chock speaks, it is on the display now, and `stop` writes it back
    /// to the real screen at the end.
    ///
    /// **What is missing, and it is missing in phantom rather than here.**
    /// `tui/caps.zig` is not re-exported by `phantom.tui`, so neither the query
    /// that went out nor the hint taken from the environment can be named by a
    /// caller; and `Session.probe` reads the terminal's reply into a local
    /// buffer and drops it, so the bytes that came back exist nowhere
    /// afterwards. What a caller can read is the decision and the mode, which
    /// are the two public fields below.
    ///
    /// **Those two still tell the two failures apart.** Every capability here
    /// is decided from one reply. All of them false is a reply that never
    /// arrived. Some of them true with `kitty_graphics` false is a reply that
    /// arrived and whose graphics answer did not match what
    /// `caps.parseReplies` looks for, which is the exact literal
    /// `APC Gi=1;OK ST` and nothing around it.
    fn sayProbe(self: *Ui, caps: anytype, mode: phantom.tui.Mode, asked: bool) void {
        if (!tty.verbose()) return;

        if (!asked) {
            self.sayFmt(.chock, "the terminal was not asked what it can do: it took no raw mode", .{});
            return;
        }

        self.sayFmt(.chock, "the terminal drawing mode is {s}", .{@tagName(mode)});
        self.sayFmt(
            .chock,
            "  it answered: graphics {s}, keyboard {s}, truecolor {s}",
            .{ yesNo(caps.kitty_graphics), yesNo(caps.kitty_keyboard), yesNo(caps.truecolor) },
        );
        self.sayFmt(
            .chock,
            "  and: sync {s}, inband resize {s}, pixel mouse {s}",
            .{ yesNo(caps.sync_output), yesNo(caps.inband_resize), yesNo(caps.sgr_pixel_mouse) },
        );

        const anything = caps.kitty_keyboard or caps.sync_output or
            caps.inband_resize or caps.sgr_pixel_mouse;
        if (!anything) {
            self.sayFmt(
                .chock,
                "  nothing came back at all, so the reply did not arrive rather than not matching",
                .{},
            );
        } else if (!caps.kitty_graphics) {
            self.sayFmt(
                .chock,
                "  a reply did arrive and its graphics answer did not match, which is phantom's matcher",
                .{},
            );
        }
    }

    /// Tell the display where this project's sessions are, and which one it is
    /// running. `src/run.zig` calls this once, beside `describe`.
    pub fn resumable(self: *Ui, sessions_dir: []const u8, current: []const u8) void {
        self.sessions_dir = sessions_dir;
        self.current_session = current;
    }

    /// Open the picker on every session of this project that could be taken up.
    ///
    /// **Every refusal is worked out here.** A session somebody else is running
    /// cannot change hands, and one that still holds work in its workspace would
    /// have that work stranded, because an adopted session builds a fresh
    /// workspace from the project's committed state. Both are the answers
    /// `chock detach` already gives, from the same two calls, so the two
    /// commands cannot drift apart.
    fn openPicker(self: *Ui) void {
        const arena = self.arena.allocator();
        if (self.sessions_dir.len == 0) {
            self.sayFmt(.chock, "this session has no directory to look in", .{});
            return;
        }

        const found = sessions_cmd.list(arena, self.io, self.sessions_dir) catch {
            self.sayFmt(.chock, "the sessions of this project could not be read", .{});
            return;
        };

        var offered: std.ArrayList(Resumable) = .empty;
        for (found) |one| {
            // This session is the one being left, so it is never offered.
            if (std.mem.eql(u8, one.id, self.current_session)) continue;

            const log_path = sessions_cmd.logPathIn(arena, self.sessions_dir, one.id) catch continue;
            const ready = sessions_cmd.readinessOf(arena, self.io, log_path, one.id);
            const refusal = refusalFor(ready, one.has_work);

            const ended = if (one.end) |reason| reason.wireName() else "no end recorded";
            const words = std.fmt.allocPrint(arena, "{s}  {s}", .{ one.id, ended }) catch one.id;
            offered.append(arena, .{
                .id = one.id,
                .words = words,
                .refusal = refusal,
            }) catch {};
        }

        if (offered.items.len == 0) {
            self.sayFmt(.chock, "this project has no other session to take up", .{});
            return;
        }
        self.picker = offered.items;
        self.picked = 0;
    }

    /// Why a session cannot be taken up, or an empty string when it can.
    ///
    /// **Two questions, and both are asked of something that already answers
    /// them.** Whether it can change hands is `sessions.readinessOf`, which is
    /// what `chock detach` asks; whether it still holds work is the listing's
    /// own `has_work`, from the same walk that produced the row. Neither is a
    /// second probe, so this command and `chock detach` cannot drift apart.
    pub fn refusalFor(ready: sessions_cmd.Readiness, has_work: bool) []const u8 {
        switch (ready) {
            .ready => {},
            .running => return "another process is running it",
            .no_such_session => return "its log is gone",
            .nothing_to_carry_on => return "it holds no conversation",
            .unknown => return "its log could not be read",
        }

        // **A workspace that still holds work.** Taking the session up builds a
        // new workspace from the project's committed state, so whatever is in
        // the old one would be left on disk with nothing pointing at it. The
        // same refusal `chock detach` gives, and the same way out of it.
        if (has_work) {
            return "it still holds work. `chock workspace` lists it and clears it";
        }
        return "";
    }

    /// Take the chosen session, or say why it cannot be taken.
    ///
    /// **The picker stays open on a refusal**, so a person who chose a session
    /// somebody else is running can choose another without typing the command
    /// again.
    fn takePicked(self: *Ui) void {
        const offered = self.picker orelse return;
        if (offered.len == 0) return;
        const chosen = offered[@min(self.picked, offered.len - 1)];

        if (chosen.refusal.len != 0) {
            self.sayFmt(.chock, "{s} cannot be taken up: {s}", .{ chosen.id, chosen.refusal });
            return;
        }

        self.taken = chosen.id;
        self.picker = null;
        self.submitted = true;
    }

    fn sayUsage(self: *Ui) void {
        self.sayFmt(.chock, "usage: {d} tokens in, {d} tokens out", .{
            self.tokens_in,
            self.tokens_out,
        });
        if (self.spent_currency.len == 0) {
            // **Never a zero.** `chock_proto.event.Cost.unknown` says the
            // provider reported nothing, and a zero would be a claim.
            self.sayFmt(.chock, "  the cost is not known for this provider", .{});
            return;
        }
        self.sayFmt(.chock, "  {d:.4} {s}", .{ self.spent, self.spent_currency });
    }

    /// Put the field up and take the terminal's settings, ready for a message.
    ///
    /// **Every turn starts here**, so nothing an earlier turn typed is carried
    /// into the next one. Raw mode is already on for the first message, because
    /// `start` turned it on for the capability probe; from the second turn on
    /// this is what turns it on again.
    ///
    /// A device that will not take raw mode still draws, and takes no key. See
    /// `start`.
    fn beginInput(self: *Ui) void {
        self.takeKeys(.FLUSH);
        self.typed.clearRetainingCapacity();
        self.submitted = false;
        self.phase = .message;
    }

    /// Put the device in raw mode, so a key arrives one at a time.
    ///
    /// **Three callers and one owner.** The message field wants keys between two
    /// turns, the approval region wants them during one, and the pump wants them
    /// for the length of one look while the session waits. None of the three can
    /// overlap: `askForMessage` runs between two calls of `Loop.run`, an approval
    /// is asked from inside one, and `pumpStep` does nothing while a question is
    /// open. So there is one flag and one `Term`, and this is the only place
    /// either is turned on. See `Keys`.
    ///
    /// **`when` is `.FLUSH` for the two that open a field or a question**, so a
    /// key already in flight when a question arrives cannot answer it, and
    /// `.NOW` for the pump, which must keep what a person typed between two of
    /// its own looks. See `pumpStep`.
    ///
    /// A device that will not take raw mode still draws, and takes no key. See
    /// `start`.
    fn takeKeys(self: *Ui, when: std.posix.TCSA) void {
        const keys = if (self.keys) |*one| one else return;
        if (keys.raw) return;
        // No settings to put on means the device never took raw mode. It still
        // draws, takes no key, and `giveKeys` has nothing to undo.
        const held = keys.held orelse return;
        self.apply_termios(keys.device.in.handle, when, held) catch return;
        keys.raw = true;
    }

    /// Whether this display can take a key at all.
    ///
    /// **False is a real case and it must not be quiet.** A window has no
    /// device here, because phantom delivers its own keys and exposes no focus
    /// manager on that session type yet; and a terminal that refused raw mode
    /// has no bounded read, so `awaitAnswer` will not read it. Either way the
    /// approval region can draw a question and cannot answer one, and the
    /// region says so on the row that would have named the keys rather than
    /// showing four keys that do nothing. See `approvalRegion`.
    pub fn answersKeys(self: *const Ui) bool {
        const keys = self.keys orelse return false;
        return keys.raw;
    }

    /// Give `ISIG` back, so `src/interrupt.zig` owns Ctrl-C again, and keep the
    /// echo off. Idempotent.
    ///
    /// **Not the settings the terminal was found in.** Those go back in
    /// `dropKeys`, once, at the end of the run. What this writes is `quietOf`
    /// them: every bit the person had except the two that echo. Read that
    /// function for why a turn that echoed corrupted the display.
    ///
    /// **The flag falls first and the write comes after**, so a device that
    /// cannot be written still leaves this file believing it holds no keyboard,
    /// which is the safe belief: `awaitAnswer` reads a device only in raw mode.
    fn giveKeys(self: *Ui, when: std.posix.TCSA) void {
        const keys = if (self.keys) |*one| one else return;
        if (!keys.raw) return;
        keys.raw = false;
        const was = keys.was orelse return;
        self.apply_termios(keys.device.in.handle, when, quietOf(was)) catch {};
    }

    /// Put the terminal exactly as it was found, at the end of the run.
    ///
    /// **The one place the echo comes back.** Every other path leaves it off for
    /// as long as the display lives: see `giveKeys`. So this is what a person
    /// gets their shell back from, and after it there is nothing left for a
    /// second Ctrl-C to undo either.
    ///
    /// Idempotent, because `stop` is.
    fn dropKeys(self: *Ui) void {
        const keys = if (self.keys) |*one| one else return;
        keys.raw = false;
        const was = keys.was orelse return;
        keys.was = null;
        keys.held = null;
        self.apply_termios(keys.device.in.handle, .FLUSH, was) catch {};
        interrupt.disarmTerminalSettings();
    }

    /// The message is in: put the terminal back and show the session instead.
    ///
    /// **Every path comes through here**, the field, a message that was already
    /// on standard input, and the teardown, so there is one moment at which
    /// Chock stops owning the terminal's settings and `src/interrupt.zig` owns
    /// Ctrl-C again. Idempotent, because more than one caller asks and none of
    /// them can know whether another did.
    pub fn endInput(self: *Ui) void {
        self.giveKeys(.FLUSH);
        self.phase = .session;
    }

    /// How much of the keyboard one turn of the message loop takes. The same
    /// bound `phantom.tui.Session.feed` holds itself to, because a single feed
    /// larger than the decoder's whole buffer can strand it mid sequence.
    const read_bytes = 64;

    /// Put one question in the approval region, and take the keyboard for it.
    ///
    /// **Every string is copied.** The caller read them out of the session log
    /// and its parse ends when it returns; a person has not read the screen yet.
    /// See `Approval`.
    ///
    /// **The region takes the focus here**, and it has to: `y` means approve
    /// only in the region that has the keyboard, and a focus that were
    /// ambiguous would let a keystroke aimed at the transcript answer a
    /// request. It also starts the settle count, so a key already in flight is
    /// ignored: see `settle_looks`.
    pub fn showApproval(self: *Ui, one: Approval) void {
        _ = self.approval_arena.reset(.free_all);
        const arena = self.approval_arena.allocator();

        var copy = one;
        copy.view = .question;
        for ([_]*[]const u8{
            &copy.action,
            &copy.summary,
            &copy.reason,
            &copy.chain,
            &copy.detail,
            &copy.review,
        }) |field| {
            // A copy that could not be made leaves an empty field rather than
            // no question at all. The action and the countdown are what a
            // person needs most and each is small; a diff is what fails first.
            field.* = arena.dupe(u8, field.*) catch "";
        }

        self.approval = copy;
        self.approval_answer = null;
        self.approval_settle = settle_looks;
        self.takeKeys(.FLUSH);
        // **A frame first, and then the focus.** Phantom builds its traversal
        // order from the mounted tree, and the region is not in that tree until
        // a frame has been built with it in. Focusing before the frame lands on
        // the transcript, which is the region a stray `y` must not reach.
        _ = self.paint();
        self.surface.focusLast();
    }

    /// Take the question down and put the terminal back.
    ///
    /// **Called on every path out of a question**, an answer, an expiry, and a
    /// Ctrl-C, so there is one moment at which the region goes and
    /// `src/interrupt.zig` owns Ctrl-C again. Idempotent.
    pub fn clearApproval(self: *Ui) void {
        if (self.approval == null) return;
        self.approval = null;
        self.approval_answer = null;
        self.approval_settle = 0;
        self.approval_focused = false;
        _ = self.approval_arena.reset(.free_all);
        self.giveKeys(.FLUSH);
        _ = self.paint();
    }

    /// Say how much time is left, so the countdown moves.
    pub fn approvalLeft(self: *Ui, left_ms: i64) void {
        if (self.approval) |*one| one.left_ms = left_ms;
    }

    /// One look at an open question: draw it, take the keys, and say what the
    /// person did.
    ///
    /// **This is what makes the region answerable during a turn.** Raw mode is
    /// off while a turn runs, because `src/interrupt.zig` owns Ctrl-C then, and
    /// an approval arrives during a turn. So the device goes into raw mode for
    /// exactly as long as a question is open and comes back out on every path,
    /// the same span `askForMessage` holds it for between two turns.
    ///
    /// **What that costs Ctrl-C, and why it costs nothing.** With `ISIG` off no
    /// `SIGINT` is sent, so a press arrives as `0x03` instead. This puts the
    /// device back first and then raises the signal itself, once per press, so
    /// the handler in `src/interrupt.zig` runs with the meaning it always had:
    /// the first press asks the session to stop, and a second press ends every
    /// running tool call through `chock_core.tools.cancelRunningTool` before it
    /// ends the process. The order is the whole of it. A raise before the
    /// device is put back would end the process with the terminal still in raw
    /// mode.
    ///
    /// **One read per look, and the device is what bounds it.** `enterRaw` sets
    /// `VMIN 0` and `VTIME 1`, so a read comes back within a tenth of a second
    /// whether or not a key arrived. That is the same order as
    /// `Broker.poll_interval_ms`, so `budget_ms` bounds the look and is never
    /// waited out: a look is short whatever it says, and the broker looks at
    /// its own deadline again the moment this returns. **Nothing here ever
    /// waits for a whole budget**, which is what keeps a question from holding
    /// the session lock past the moment it expires.
    ///
    /// **A window has no device, so the budget is what the look waits on.** See
    /// `lookWait`: it is the shorter of the budget and one look, so a display
    /// with no keyboard waits exactly as long as one with a keyboard reads for,
    /// and never past the deadline the caller gave.
    pub fn awaitAnswer(self: *Ui, budget_ms: u64) Look {
        if (self.approval == null) return .waiting;

        // **The region keeps the focus while the question is open.** That is
        // what makes `Esc` unable to dismiss an approval: phantom's focus
        // manager answers Escape in its traversal rules by clearing the focus,
        // before any listener is offered the key, and this takes it straight
        // back. An approval is not dismissable.
        if (!self.approval_focused) self.surface.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            // The display said stop: a window closed, or a terminal went away.
            // A session that carried on with nothing showing it would be a
            // runaway, and nothing was decided. See `draw`.
            self.running = false;
            interrupt.requestStop();
            return .canceled;
        }

        if (self.approval_answer) |said| {
            self.approval_answer = null;
            return .{ .answered = said };
        }

        // **Only in raw mode**, and that is not the same guard `askForMessage`
        // keeps. `VMIN 0` and `VTIME 1` are what bound the read, and they are
        // set by `enterRaw`; a read of a device that refused raw mode would
        // block until a key arrived, with the session lock held, which is the
        // one thing an approval may never do. A device like that draws the
        // question and answers nothing, and a client on the approval socket can
        // still answer it.
        if (self.answersKeys()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                // Nothing arrived. `VTIME 1` reads that as the end of the
                // stream every tenth of a second: see `askForMessage`.
                error.EndOfStream => 0,
                // A device that cannot be read cannot answer. The question
                // stays open in the log for a client of the approval socket.
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                // The device first, then the signal. See this function's own
                // doc comment: the order is the whole of it.
                self.giveKeys(.FLUSH);
                // A raise that fails leaves the flag unset, and a session
                // nobody can stop is worse than one that stopped without the
                // handler's own line on the screen. So the flag is set by hand
                // there, which is the one thing the handler would have done.
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return .canceled;
            }
            if (read > 0) keys.session.feed(said);
        }

        if (self.approval_settle > 0) self.approval_settle -= 1;

        if (self.approval_answer) |said| {
            self.approval_answer = null;
            return .{ .answered = said };
        }
        return .waiting;
    }

    /// One look while the session is waiting for something else: read what has
    /// been typed, and draw one frame.
    ///
    /// ## The fault this exists for
    ///
    /// `draw` is the only place a key is read and the screen repaints, and it is
    /// called from four places, every one of them an event arriving: a person
    /// pressed Enter, a record was appended, a token streamed in, a notice was
    /// raised. **Between two events nothing reads the keyboard**, so the display
    /// was frozen while the harness waited for the first token of a reply, and
    /// frozen for the whole of a tool call. During streaming it thawed once per
    /// token, which is why it read as intermittent rather than dead.
    ///
    /// **A second thread is not the answer, and must never become one.** The
    /// sandbox needs a single threaded caller: `fork` carries only the calling
    /// thread and `namespace.enter` refuses a process with more than one, which
    /// is why a subagent is a child process. A display thread running at the
    /// moment a tool call forks would break the sandbox, and the sandbox is the
    /// product. So this runs on the one thread that was going to sit in the wait
    /// anyway: see `chock_core.idle.Idle`, and `src/run.zig`, which is what puts
    /// this behind it.
    ///
    /// ## It draws, and it appends nothing
    ///
    /// **A frame, and not only a read.** `phantom.tui.Session.step` is one call
    /// that dispatches the keys and paints, so the two cannot be separated; a
    /// key that scrolled the transcript would change nothing a person can see
    /// until the next event arrived. A running tool call's duration is drawn
    /// from the clock as well, so without a frame it stands still at the moment
    /// the call started. Phantom writes only the cells that changed, so a frame
    /// in which nothing moved reaches the terminal as nothing at all.
    ///
    /// **No row is added here.** The newest rows go on arriving exactly as they
    /// did, through `foldEvent` and `onPieceFn`; this shows what is already
    /// there. `scroll_back` is untouched, so a person who has scrolled back
    /// stays where they scrolled to.
    ///
    /// ## The keyboard is taken for one look and given straight back
    ///
    /// **Not held for the length of the wait**, which is the whole of what keeps
    /// Ctrl-C behaving as it did. Raw mode turns `ISIG` off, so a press arrives
    /// as `0x03` and only somebody reading the device can act on it. Between two
    /// looks the device is in the person's own settings, `ISIG` and all, and the
    /// kernel raises `SIGINT` the moment the key is pressed, which is what
    /// `src/interrupt.zig` is waiting for: the first press asks the session to
    /// stop and the second ends every running tool call through
    /// `chock_core.tools.cancelRunningTool`. A press that lands inside a look is
    /// read as a byte instead, and is turned back into the same signal in the
    /// same order `awaitAnswer` uses: the device first, then the raise.
    ///
    /// **`.NOW` and not `.FLUSH`**, which is the one difference from every other
    /// caller of `takeKeys`. `TCSAFLUSH` throws away what has not been read, and
    /// a person typing between two looks would lose the keys they pressed.
    ///
    /// ## What it does nothing at all for
    ///
    /// A display that is replaying a log, a session that has stopped, and a
    /// display with a question open. The last one matters: an approval and an
    /// ask each hold the keyboard themselves for as long as the question is up,
    /// through `awaitAnswer` and `awaitText`, and a second reader of one device
    /// races for every byte.
    pub fn pumpStep(self: *Ui) void {
        if (self.replaying) return;
        if (!self.running) return;
        // A question owns the keyboard while it is open, and it is looked at on
        // its own poll. See this function's own doc comment.
        if (self.approval != null or self.question != null) return;
        // Between two turns the message field owns the device, and it is drawing
        // and reading already. Nothing waits on this library then.
        if (self.phase != .session) return;

        // **Before the frame**, so the frame this look draws is the one that
        // carries it. See `noteStopping`.
        self.noteStopping();

        self.takeKeys(.NOW);
        defer self.giveKeys(.NOW);

        // **The keys before the frame**, so a key that scrolled the transcript
        // is shown by this frame rather than by the next one. `feed` only hands
        // the bytes to phantom's decoder; `paint` is what dispatches them.
        if (self.answersKeys() and self.typedSomething()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                // Nothing arrived. `VTIME 1` reads that as the end of the
                // stream every tenth of a second: see `askForMessage`.
                error.EndOfStream => 0,
                // A device that cannot be read is a device with nobody at it.
                // The session carries on; it is not this call's place to stop
                // one over a keyboard.
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                // The device first, then the signal, which is the same order
                // `awaitAnswer` keeps and for the same reason: a raise before
                // the device is put back ends the process with the terminal
                // still raw. The `defer` above has not run yet, so this is the
                // call that does it, and `giveKeys` is idempotent.
                self.giveKeys(.NOW);
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return;
            }
            if (read > 0) keys.session.feed(said);
        }

        if (self.paint()) return;

        // The display said stop: a window closed, or a terminal went away. A
        // session that carried on with nothing showing it would be a runaway.
        // See `draw`.
        self.running = false;
        interrupt.requestStop();
    }

    /// Whether there is a key waiting to be read right now.
    ///
    /// **Asked so that a look is short.** Raw mode's own `VTIME 1` bounds a read
    /// at a tenth of a second, and a pump that spent that on every look while
    /// nobody typed would double the time the caller's own wait takes to come
    /// back around. This asks the device instead, with no wait at all, and reads
    /// only when there is something to read.
    ///
    /// **True is the safe answer to a question this cannot settle.** A poll that
    /// cannot run leaves the read exactly as it was, which is the behaviour this
    /// is an improvement on.
    fn typedSomething(self: *Ui) bool {
        const keys = if (self.keys) |*one| one else return false;
        var fds = [_]std.posix.pollfd{.{
            .fd = keys.device.in.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 0) catch return true;
        return ready != 0;
    }

    /// Put one question from the agent on the screen, and take the keyboard for
    /// it.
    ///
    /// **Before this existed, a session with a display told the agent nobody was
    /// asked.** `src/run.zig` gave `chock_core.ask.Prompt.at_terminal` a false
    /// whenever a display was up, because the display holds the terminal in raw
    /// mode and keeps a copy of every cell, so a prompt written around it lands
    /// in cells it believes it owns and two readers race for every byte. That
    /// was the honest half of a half built feature: with no region to show a
    /// question in, claiming somebody was there would have hung the session. This
    /// is the other half.
    ///
    /// **Every string is copied**, for the reason `showApproval` copies its own:
    /// the caller read them out of a tool call whose parse ends when it returns.
    ///
    /// **The region takes the focus here**, so `Enter` means "send this answer"
    /// only in the region that has the keyboard. It also starts the settle
    /// count, so a key already in flight cannot answer a question that was not
    /// on screen when it was pressed: see `settle_looks`.
    pub fn showQuestion(self: *Ui, one: Question) void {
        _ = self.question_arena.reset(.free_all);
        const arena = self.question_arena.allocator();

        var copy = one;
        // A copy that could not be made leaves an empty field rather than no
        // question at all: the deadline and the answer line are what a person
        // needs most, and neither is a copy.
        copy.agent_kind = arena.dupe(u8, one.agent_kind) catch "";
        copy.text = arena.dupe(u8, one.text) catch "";
        copy.options = dupeOptions(arena, one.options);

        self.question = copy;
        self.question_filled = 0;
        self.question_said = null;
        self.question_settle = settle_looks;
        self.takeKeys(.FLUSH);
        // **A frame first, and then the focus**, for the reason `showApproval`
        // gives: phantom builds its traversal order from the mounted tree, and
        // the region is not in that tree until a frame has been built with it.
        _ = self.paint();
        self.surface.focusLast();
    }

    /// Take the question down and put the terminal back.
    ///
    /// **Called on every path out of a question**, an answer, a decline, an
    /// expiry and a Ctrl-C, so there is one moment at which the region goes and
    /// `src/interrupt.zig` owns Ctrl-C again. Idempotent.
    pub fn clearQuestion(self: *Ui) void {
        if (self.question == null) return;
        self.question = null;
        self.question_said = null;
        self.question_filled = 0;
        self.question_settle = 0;
        self.question_focused = false;
        _ = self.question_arena.reset(.free_all);
        self.giveKeys(.FLUSH);
        _ = self.paint();
    }

    /// Say how much time is left, so the countdown moves.
    pub fn questionLeft(self: *Ui, left_ms: i64) void {
        if (self.question) |*one| one.left_ms = left_ms;
    }

    /// One look at an open question: draw it, take the keys, and say what the
    /// person did.
    ///
    /// **The same shape `awaitAnswer` has, and for the same reasons.** Raw mode
    /// is off while a turn runs so that `src/interrupt.zig` owns Ctrl-C, and a
    /// question arrives during a turn; so the device is in raw mode for exactly
    /// as long as the question is open and comes out of it on every path. A
    /// Ctrl-C read as `0x03` puts the device back first and raises the signal
    /// afterwards, because a raise before that would end the process with the
    /// terminal still raw.
    ///
    /// **One read per look, and the device is what bounds it**, so `budget_ms`
    /// bounds the look and is never waited out: `VMIN 0` and `VTIME 1` bring a
    /// read back within a tenth of a second whether or not a key arrived, and
    /// the caller looks at its own deadline again the moment this returns.
    /// **Nothing here waits for a whole budget**, which is what keeps a
    /// question from holding the session past the moment it expires.
    ///
    /// **A window has no device, so the budget is what the look waits on.** See
    /// `lookWait`, and `awaitAnswer`, which keeps the same rule.
    ///
    /// **This answers no approval and can produce no decision.** The only
    /// values it gives back are words, no answer, and two ways of ending: see
    /// `Text`.
    pub fn awaitText(self: *Ui, budget_ms: u64) Text {
        if (self.question == null) return .waiting;

        // The region keeps the focus while the question is open, which is what
        // makes `Esc` unable to dismiss it: phantom's focus manager answers
        // Escape in its traversal rules by clearing the focus, before any
        // listener is offered the key, and this takes it straight back.
        if (!self.question_focused) self.surface.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            // The display said stop: a window closed, or a terminal went away.
            // Nothing was said, and the session is ending. See `draw`.
            self.running = false;
            interrupt.requestStop();
            return .canceled;
        }

        if (self.takeSaid()) |said| return said;

        // **Only in raw mode.** A read of a device that refused raw mode would
        // block until a key arrived, with the session held, which is the one
        // thing a question may never do. Such a display draws the question and
        // answers nothing, and the deadline is what ends it.
        if (self.answersKeys()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                // The device first, then the signal. The order is the whole of
                // it: see `awaitAnswer`.
                self.giveKeys(.FLUSH);
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return .canceled;
            }
            if (read > 0) keys.session.feed(said);
        }

        if (self.question_settle > 0) self.question_settle -= 1;

        if (self.takeSaid()) |said| return said;
        return .waiting;
    }

    /// What the region's own key listener finished with, taken once.
    fn takeSaid(self: *Ui) ?Text {
        const said = self.question_said orelse return null;
        self.question_said = null;
        return switch (said) {
            .declined => .declined,
            // Borrowed, and named as such on `Text.answered`: the caller copies
            // it before the next look overwrites the buffer.
            .answered => .{ .answered = self.question_typed[0..self.question_filled] },
        };
    }

    /// How many rows the question region wants, and zero when there is none.
    ///
    /// **It grows with the question and stops at half the screen**, which is
    /// the rule the open approval views already follow: the transcript is given
    /// up first, and a question longer than that is read a screen at a time in
    /// the transcript, where the `tool.call` row also holds it.
    pub fn questionRows(self: *const Ui) u16 {
        const one = self.question orelse return 0;
        // The header, the answer line, and the keys row: the three rows that are
        // Chock's own and are never dropped.
        var wanted: usize = 3 + countLines(one.text) + one.options.len;
        if (one.options.len != 0) wanted += 1; // the blank row before the list
        const half: u16 = @max(question_rows_min, self.rows / 2);
        const asked: u16 = @intCast(@min(wanted, std.math.maxInt(u16)));
        return @min(@max(question_rows_min, asked), half);
    }

    /// The fewest rows a question is ever shown in: the header, one row of the
    /// question, the answer line, and the keys.
    const question_rows_min: u16 = 4;

    /// How many rows the raised panel wants, whichever of the two is open.
    ///
    /// **An approval and a question are never open together**, so the panel is
    /// one or the other and `split` has one number to work with. A turn asks for
    /// one thing at a time: the broker holds the session for the whole of an
    /// approval, and `chock_core.Loop`'s own `ask_user` call holds it for the
    /// whole of a question.
    ///
    /// **Two regions and not one**, and that stays true however alike they look.
    /// See `Question`: an ask grants nothing, and a shared implementation is the
    /// road by which it would start to.
    pub fn panelRows(self: *const Ui) u16 {
        if (self.approval != null) return self.approvalRows();
        return self.questionRows();
    }

    /// How many rows the approval region wants.
    ///
    /// **Zero when there is no question**, which is what makes the region
    /// absent rather than empty, so that its arrival is the signal. `split` is
    /// what turns this into rows on a screen.
    pub fn approvalRows(self: *const Ui) u16 {
        const one = self.approval orelse return 0;
        return switch (one.view) {
            .question => question_rows,
            // The whole of a diff will not fit on any screen, so the open views
            // take half of what there is and the transcript keeps the rest. The
            // transcript is given up first and this is the same rule from the
            // other side.
            .diff, .why => @max(question_rows, self.rows / 2),
        };
    }

    /// The rows the question view needs: the action and the countdown, the
    /// chain, the summary, the reason, the effect, and the keys.
    const question_rows: u16 = 6;

    /// Connect the observer whose bytes this display shows.
    ///
    /// **Called once the session exists**, which is after the message was typed:
    /// see `start`. `src/run.zig` is the only caller.
    pub fn wrap(self: *Ui, inner: chock_core.Loop.Observer) void {
        self.inner = inner;
    }

    /// Tell the header what this session is.
    ///
    /// **Called at the same moment as `wrap`**, and by the same one caller, for
    /// the same reason: these are facts only `src/run.zig` holds. See `Facts`,
    /// which also says which fact is still missing and why the band exists
    /// without it.
    pub fn describe(self: *Ui, facts: Facts) void {
        self.facts = facts;
    }

    /// Give the display the message it is to send first, instead of asking for
    /// one.
    ///
    /// **So a piped run and a typed one take one path.** `echo "fix the parser"
    /// | chock` on a terminal has its message before the display is up, and
    /// every turn after it is typed. Both go through `askForMessage`, and only
    /// the first answer differs. Borrowed: it lives in `src/run.zig`'s arena.
    pub fn prime(self: *Ui, message: []const u8) void {
        self.primed = message;
    }

    /// Give the display back and put the transcript where a terminal user
    /// expects to find it.
    ///
    /// **The order is the whole of it.** The session comes down first, which
    /// leaves the alternate screen and puts the real one back with whatever was
    /// on it before the session started. Then the transcript is written to that
    /// screen, so the scrollback holds the session exactly as a run with no
    /// display would have left it.
    pub fn stop(self: *Ui) void {
        // **Idempotent, because two callers ask for it and neither can know
        // whether the other did.** `src/run.zig` gives the display back at the
        // end of the session, before its own teardown prints anything a person
        // has to read; `start` asks again on the paths that never reached a
        // session at all.
        if (self.stopped) return;
        self.stopped = true;
        // A run that never got as far as a message still owns the terminal's
        // settings, and they go back before anything else. **`dropKeys` and not
        // `endInput` alone**: between two turns the echo is still off, and the
        // shell a person is given back has to show what they type in it.
        self.endInput();
        self.dropKeys();

        self.surface.deinit();
        tty.flushOut();
        // The screen is down, so there is nothing left for a second press to
        // put back. Harmless for a window, which never armed it.
        interrupt.disarmTerminalRestore();

        // **After the screen is down and before the transcript goes out.**
        // Anything the teardown above wrote is still a diagnostic under a
        // display, so it becomes a row and travels out with everything else;
        // anything written after this reaches the real terminal, which is now
        // the only screen there is. See `Diagnostics.finish`.
        self.diagnostics.finish(self.io);

        // **Written for both backends.** A window run was started from a
        // terminal too, and the session belongs in that terminal's scrollback
        // exactly as `chock run` would have left it.
        _ = tty.writeOut(self.transcript.items);
        tty.flushOut();
    }

    /// Give the display back, if that has not happened, and free everything.
    ///
    /// **Apart from `stop`, because the transcript outlives the display.** The
    /// session keeps writing into it right up to the last event, and `stop` is
    /// what puts it on the real screen; freeing it is a separate moment, and
    /// only the caller that owns the whole run knows when that is.
    pub fn deinit(self: *Ui) void {
        const gpa = self.gpa;
        self.stop();
        switch (self.surface) {
            .terminal => |one| gpa.destroy(one),
            .window => |one| gpa.destroy(one),
        }
        self.arena.deinit();
        self.approval_arena.deinit();
        self.question_arena.deinit();
        self.transcript.deinit(gpa);
        self.diagnostics.held.deinit(gpa);
        self.typed.deinit(gpa);
        self.pending.deinit(gpa);
        self.reasoning.deinit(gpa);
        self.dropRunning();
        for (self.lines.items) |line| self.freeLine(line);
        self.lines.deinit(gpa);
        gpa.destroy(self);
    }

    pub fn observer(self: *Ui) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    /// **Passed on first, then recorded, then drawn.** The wrapped observer is
    /// what writes the transcript, and a frame drawn before the call was passed
    /// on would be one word behind for ever.
    ///
    /// **Which voice a line is in comes from which call delivered it**, and from
    /// nothing else. See `Voice`.
    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onEvent(id, ev);
        self.foldEvent(id, ev);
    }

    /// Turn one event into the rows it is drawn as.
    ///
    /// **Apart from the observer call, because a replay is not an observation.**
    /// See `replay`: a log that has already been written reaches the display and
    /// stops there.
    fn foldEvent(self: *Ui, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        switch (ev) {
            .plan_update => |update| self.foldPlan(update),
            .message => |m| switch (m.role) {
                // What the model said, whole. Every word of it has already
                // arrived through `onPiece` and been shown, so this only closes
                // the line: see `streamed`. A turn that was reasoning and
                // nothing else still leaves that reasoning on a row of its own.
                .assistant => {
                    self.foldReasoning();
                    self.endLine();
                    self.turn_open = false;
                },
                // The harness talking to the model. Chock's own words.
                .system => for (m.content) |part| {
                    if (part == .text) self.say(.chock, part.text);
                },
                else => {},
            },
            .tool_call => |call| self.beginCall(call),
            .tool_result => |result| self.finishCall(result),
            // **A rule row, and not a gap.** It is not a gap and not a `...`,
            // because those read as loss. So it says how much was folded and
            // that the log keeps it, and the summary a model wrote is one key
            // underneath.
            //
            // **It keeps the rail, and the design's own drawing does not.**
            // Chock folded the context, so Chock is what says so, and a row at
            // column 0 with no rail is a shape only the agent's own indent has.
            // The rule glyphs come after the rail rather than instead of it.
            .compaction => |folded| {
                var buffer: [128]u8 = undefined;
                const said = std.fmt.bufPrint(
                    &buffer,
                    "\u{2500}\u{2500} events {d} to {d} folded. The log keeps them.",
                    .{ folded.from_id, folded.through_id },
                ) catch "\u{2500}\u{2500} the context was folded. The log keeps it.";
                self.sayFolded(.chock, said, .compaction, folded.summary);
            },
            // **One line, and the child's turns never appear here.** The
            // subagent does not inline. One line says it started, what kind,
            // which model, and that it can be opened.
            .session_spawn => |spawn| {
                var buffer: [256]u8 = undefined;
                const said = std.fmt.bufPrint(&buffer, "started a subagent, {s}", .{
                    spawn.child_agent_kind,
                }) catch "started a subagent";
                self.sayFolded(.chock, said, .subagent, spawn.reason);
            },
            .agent_complete => |done| {
                var buffer: [256]u8 = undefined;
                const said = std.fmt.bufPrint(&buffer, "the subagent {s} came back, {s}", .{
                    done.child_agent_kind,
                    done.outcome.wireName(),
                }) catch "a subagent came back";
                self.sayFolded(.chock, said, .subagent, done.result);
            },
            .task_complete => |done| self.sayFmt(.chock, "the background task {s} finished, {s}", .{
                done.task_id,
                done.status.wireName(),
            }),
            .policy_self => |update| for (update.restrictions) |one| {
                self.sayFmt(.chock, "the agent promised {s} at most {s}", .{
                    one.action,
                    one.ceiling.wireName(),
                });
            },
            .session_end => |ended| self.sayFmt(.chock, "session ended, {s}", .{ended.reason.wireName()}),
            // **Folded and not shown.** A count after every turn would be noise
            // in the one region a person is reading; `/usage` is where it is
            // asked for. The whole record is in the log either way.
            .usage => |spent| {
                self.tokens_in += spent.input_tokens +
                    spent.cache_creation_input_tokens +
                    spent.cache_read_input_tokens;
                self.tokens_out += spent.output_tokens;
                switch (spent.cost) {
                    .known => |amount| {
                        self.spent += amount.value;
                        self.spent_currency = amount.currency;
                    },
                    // Every other case leaves the currency empty, which is what
                    // `/usage` reads as "not known". A zero would be a claim.
                    .free, .unknown, .unrecognized => {},
                }
            },
            else => {},
        }
        self.draw();
    }

    /// Fold an event that a log already holds into the transcript.
    ///
    /// **A session that was taken up opens on what came before it.** Nothing
    /// replays a log into the display today, so a resumed session shows an
    /// empty transcript and reads as a fresh one. This is the display's half of
    /// that: the caller reads the log and hands each event over, in order,
    /// before the first turn runs.
    ///
    /// **Two arms differ from a live event and the rest do not.** A live
    /// assistant turn arrives word by word through `onPiece` and its `message`
    /// event only closes the row, so on a replay there is no stream and the
    /// words are read off the message itself. A `user` message is never shown
    /// live at all, because the display already wrote it when the person sent
    /// it, and on a replay it is the only record of what was asked.
    ///
    /// **Nothing is passed on to the inner observer.** The observer under this
    /// one keeps the plain record of THIS run, and a log that has already been
    /// written is not something this run wrote.
    ///
    /// **No frame is drawn, however many events arrive.** See `draw` for the
    /// cost that would be, and `replaying` for the flag that says so. The rows
    /// are kept, and `Ui.kept_lines` is what bounds a very long log: the oldest
    /// go, so a display opens on the newest screenful of what came before it.
    pub fn replay(self: *Ui, id: u64, ev: chock_proto.event.Event) void {
        self.replaying = true;
        defer self.replaying = false;
        switch (ev) {
            .message => |m| switch (m.role) {
                .assistant => {
                    self.openTurn();
                    for (m.content) |part| {
                        if (part == .text) self.say(.agent, part.text);
                    }
                    self.endLine();
                    self.turn_open = false;
                },
                .user => for (m.content) |part| {
                    if (part == .text) self.saidByUser(part.text);
                },
                else => self.foldEvent(id, ev),
            },
            else => self.foldEvent(id, ev),
        }
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onPiece(piece);
        // **The reasoning is kept and folded, and the answer is shown.**
        // Reasoning arrives before the text and is usually long, so it gets a
        // size and a marker and it opens. It is never hidden with no trace,
        // because it is part of the turn.
        switch (piece) {
            .text => |text| {
                self.openTurn();
                self.foldReasoning();
                self.say(.agent, text);
            },
            .reasoning => |text| {
                self.openTurn();
                self.reasoning.appendSlice(self.gpa, text) catch {};
            },
        }
        self.draw();
    }

    /// The header a turn opens with: which model answered, and when.
    ///
    /// **Once per turn, and only when the model says something.** A header on a
    /// turn with nothing under it would be a row that says a turn happened,
    /// which the rows under it already say.
    ///
    /// **The agent's own indent**, because it names the agent and stands at the
    /// head of the agent's words. Chock composes it, and it says nothing an
    /// agent supplies: the model and the provider come from `Facts`, which
    /// `src/run.zig` hands over, and the time comes from `clock`.
    fn openTurn(self: *Ui) void {
        if (self.turn_open) return;
        self.turn_open = true;
        // A turn is a block, and it is the one the rhythm is drawn around. See
        // `startBlock`.
        self.startBlock();
        if (self.facts.model.len == 0) return;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const at = clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch return;
        const who = if (self.facts.provider.len == 0)
            self.facts.model
        else
            std.fmt.allocPrint(arena, "{s} \u{b7} {s}", .{
                self.facts.model,
                self.facts.provider,
            }) catch self.facts.model;
        // The clock rides on the row rather than being padded into it, so it
        // is still against the right hand edge after the window moves. See
        // `Line.pinned`.
        self.sayPinned(.agent, who, at);
    }

    /// Put the reasoning of this turn on a row of its own, if there is any.
    fn foldReasoning(self: *Ui) void {
        if (self.reasoning.items.len == 0) return;
        var buffer: [64]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buffer);
        const size = sizeText(fixed.allocator(), self.reasoning.items.len) catch "some";

        var said: [96]u8 = undefined;
        const text = std.fmt.bufPrint(&said, "{s} of reasoning", .{size}) catch "reasoning";
        self.sayFolded(.agent, text, .reasoning, self.reasoning.items);
        self.reasoning.clearRetainingCapacity();
    }

    /// A tool call was asked for. One row, with the tool, the argument as a
    /// person reads it, and the glyph a running call gets.
    ///
    /// **The same row is written again when the call comes back**, so a call
    /// and its outcome are one row and not two. See `finishCall`.
    fn beginCall(self: *Ui, call: chock_proto.event.ToolCall) void {
        // A call that never answered: this one found the last still running.
        // Its row keeps the glyph that says it was going, and the record of it
        // is dropped so this call's duration is measured from now.
        self.dropRunning();
        // A call and its result are a block, so a blank row goes before the
        // call and never between it and what it answered. See `startBlock`.
        self.startBlock();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // **One tool reads its own arguments differently, and it is the one
        // whose argument is a sentence.** See `askArgumentText`.
        const argument = if (std.mem.eql(u8, call.tool, chock_core.Loop.ask_tool_name))
            askArgumentText(arena, call.arguments) catch call.arguments
        else
            argumentText(arena, call.arguments) catch call.arguments;
        const tool = self.gpa.dupe(u8, call.tool) catch return;
        const kept = self.gpa.dupe(u8, argument) catch {
            self.gpa.free(tool);
            return;
        };
        self.running_call = .{ .tool = tool, .argument = kept, .at_ms = self.clock.now() };

        self.sayPinned(.agent, callText(arena, "\u{22ef}", tool, kept) catch "", "");
        self.running_row = if (self.lines.items.len == 0) null else self.lines.items.len - 1;
    }

    /// The words of one tool call row: a glyph, the tool, and its argument.
    ///
    /// **The right hand column is not here.** A duration is carried on the row
    /// and laid out at draw time, so the row still reads correctly after the
    /// window moves. See `Line.pinned`.
    fn callText(
        arena: std.mem.Allocator,
        glyph: []const u8,
        tool: []const u8,
        argument: []const u8,
    ) std.mem.Allocator.Error![]const u8 {
        return std.fmt.allocPrint(arena, "{s} {s}  {s}", .{ glyph, tool, argument });
    }

    /// A tool call answered.
    ///
    /// **Two rows and never the output.** The call's own row gains the outcome
    /// glyph and the duration, and under it goes one line derived from the
    /// result with the whole of the result folded behind it. That is the fix: a
    /// result is one line.
    ///
    /// **The summary is the agent's**, because it is derived from the agent's
    /// own bytes, so it goes in the agent's voice at the agent's indent and
    /// carries no rail. Nothing about it may read as Chock speaking.
    fn finishCall(self: *Ui, result: chock_proto.event.ToolResult) void {
        self.endLine();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // A glyph that survives a terminal with no colour, and a different one
        // for failed than for anything else.
        const glyph = if (result.is_error) "\u{2717}" else "\u{2713}";
        if (self.running_call) |call| {
            const took = durationText(arena, self.clock.now() - call.at_ms) catch "";
            const said = callText(arena, glyph, call.tool, call.argument) catch "";
            self.rewriteRunningRow(said, took);
        }
        self.dropRunning();

        // **Chock's own sentence, above the agent's row and under the rail.**
        // A tool result has two readers: the model reads `output`, which is
        // written to the model and says what the agent may do next, and the
        // person reads this. The two are told apart the way every other pair
        // of voices in this file is, by the rail and the indent, and by
        // nothing else: see `Voice`. Written before the summary so a person
        // who acts on the first line they can act on reads Chock's and not the
        // agent's. See `chock_proto.event.ToolResult.note`.
        if (result.note.len != 0) {
            self.say(.chock, result.note);
            self.endLine();
        }

        const summary = summaryText(
            arena,
            result.output,
            result.is_error,
            result.truncated,
        ) catch "no output";
        self.sayFolded(.agent, summary, .result, result.output);
    }

    /// Put `text` on the row the running call was drawn on.
    fn rewriteRunningRow(self: *Ui, text: []const u8, right: []const u8) void {
        const at = self.running_row orelse return;
        if (at >= self.lines.items.len) return;
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, right) catch {
            self.gpa.free(kept);
            return;
        };
        self.gpa.free(self.lines.items[at].text);
        self.gpa.free(self.lines.items[at].pinned);
        self.lines.items[at].text = kept;
        self.lines.items[at].pinned = held;
    }

    /// Forget the running call. Its row is left exactly as it stands.
    fn dropRunning(self: *Ui) void {
        if (self.running_call) |call| {
            self.gpa.free(call.tool);
            self.gpa.free(call.argument);
        }
        self.running_call = null;
        self.running_row = null;
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onNotice(text);
        // Chock speaking is a block of its own, for the reason `startBlock`
        // gives.
        self.startBlock();
        self.say(.chock, text);
        self.endLine();
        self.draw();
    }

    /// The most of one tool result a line keeps. The whole of it is in the log
    /// and in the transcript, which is where somebody who wants it goes.
    const shown_line_bytes = 400;

    /// How many rows are kept. The display shows at most a screenful, and the
    /// whole session is in the transcript and in the log, so an older row costs
    /// memory for nothing. Enough for a long screen and a scroll back later.
    const kept_lines = 512;

    /// Add `text` to the transcript in `voice`, splitting it into rows.
    ///
    /// **A change of voice closes the row that was open.** Two voices cannot
    /// share a row, or the agent's words would be under Chock's rail.
    /// **A newline always ends a row, even an empty one.** An agent writing a
    /// structured answer puts a blank line between its sections, and dropping
    /// those turns the answer into one paragraph. `endLine` closes a row only
    /// when there is something in it, which is right for a caller closing
    /// whatever was open and wrong for a newline the agent really wrote, so a
    /// newline uses `endRow` instead.
    ///
    /// **That blank row is the agent's own content**, so it is in the agent's
    /// voice and keeps the agent's indent. It is not the blank row between two
    /// blocks: see `startBlock` and `Line.gap`.
    fn say(self: *Ui, voice: Voice, text: []const u8) void {
        if (voice != self.pending_voice) self.endLine();
        self.pending_voice = voice;

        var rest = text;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |at| {
            self.pending.appendSlice(self.gpa, rest[0..at]) catch {};
            self.endRow();
            self.pending_voice = voice;
            rest = rest[at + 1 ..];
        }
        self.pending.appendSlice(self.gpa, rest) catch {};
    }

    /// `say`, with the words built from a format. Dropped rather than reported
    /// when it cannot be built: an observer watches and never decides.
    fn sayFmt(self: *Ui, voice: Voice, comptime fmt: []const u8, args: anytype) void {
        var buffer: [shown_line_bytes + 128]u8 = undefined;
        const said = std.fmt.bufPrint(&buffer, fmt, args) catch buffer[0..];
        self.say(voice, said);
        self.endLine();
    }

    /// The most of one folded body this keeps. The whole of it is in the log
    /// and in the transcript, which is where somebody who wants all of it goes.
    ///
    /// **A bound, because a body is a tool's own output.** A session that read
    /// twenty large files would otherwise hold every one of them twice.
    const kept_body_bytes = 16 * 1024;

    /// The most rows an open body puts on the screen.
    ///
    /// **A frame is built for a screen, and a screen is tens of rows.** A body
    /// of sixty thousand lines would cost a frame's arena a megabyte to lay out
    /// rows nobody can reach. The row under the last one says how many are not
    /// there.
    const open_body_rows = 200;

    /// The whole width of the display, and the face it draws in.
    fn screenRoom(self: *const Ui) Room {
        return .{ .measure = self.measure, .width = self.width };
    }

    /// How much room the transcript draws in.
    ///
    /// **Not always every column there is.** See `readable_columns`: a very
    /// wide display stops the transcript growing and leaves the rest as margin.
    /// Every other region still uses the whole width, because a header and an
    /// approval are facts in a row and not prose to read across.
    ///
    /// **The design measure is turned into a width once, here.** It is stated
    /// in characters and the face has no column, so `Measure.step` converts it:
    /// see its own doc comment for why nothing is ever fitted against that.
    fn transcriptRoom(self: *const Ui) Room {
        return self.transcriptBandRoom().upTo(@as(f32, readable_columns) * self.measure.step());
    }

    /// How wide the plan sidebar is drawn, and zero when it is not drawn.
    ///
    /// **The one place the sidebar's width is decided.** The band, the rows in
    /// it and the room the transcript is left are all worked out from this, so
    /// none of them can answer differently.
    ///
    /// **Refused rather than squeezed.** A window under the design width shows
    /// no sidebar however the flag stands: see `sidebar_needs_columns`. A
    /// person who shrinks the window watches it go and gets the whole width
    /// back for the transcript, and a person who grows it again gets it back.
    fn sidebarWidth(self: *const Ui) f32 {
        if (!self.sidebar_open) return 0;
        if (!self.fitsSidebar()) return 0;
        return @as(f32, sidebar_columns) * self.measure.step();
    }

    /// Whether this display is wide enough for a sidebar beside the transcript.
    fn fitsSidebar(self: *const Ui) bool {
        return self.width >= @as(f32, sidebar_needs_columns) * self.measure.step();
    }

    /// The room the transcript's own band has, once the sidebar has taken its
    /// width. What every row drawn inside that band is cut to: the rule, the
    /// completion list, the picker, and the pane over it.
    fn transcriptBandRoom(self: *const Ui) Room {
        const room = self.screenRoom();
        const side = self.sidebarWidth();
        return .{
            .measure = room.measure,
            .width = if (room.width > side) room.width - side else 0,
        };
    }

    /// The room one row of the sidebar has.
    fn sidebarRoom(self: *const Ui) Room {
        return .{ .measure = self.measure, .width = self.sidebarWidth() };
    }

    /// How wide a row in `voice` is, once that voice's own leading structure is
    /// taken off.
    fn roomFor(self: *const Ui, voice: Voice) Room {
        return self.transcriptRoom().less(voice.prefix());
    }

    /// How wide the agent's own rows are, once the indent is taken off.
    fn agentRoom(self: *const Ui) Room {
        return self.roomFor(.agent);
    }

    /// Close the row being written, if there is anything in it.
    ///
    /// **For a caller that is about to draw something else**, which is what
    /// every caller of this is. A row nobody put anything in is nothing to
    /// close.
    fn endLine(self: *Ui) void {
        if (self.pending.items.len == 0) return;
        self.endRow();
    }

    /// Close the row being written, whether or not anything was put in it.
    ///
    /// **For a newline the agent really wrote**, which is a row even when it is
    /// empty. See `say`.
    fn endRow(self: *Ui) void {
        const kept = self.gpa.dupe(u8, self.pending.items) catch {
            self.pending.clearRetainingCapacity();
            return;
        };
        self.pending.clearRetainingCapacity();
        self.addLine(.{ .voice = self.pending_voice, .text = kept });
    }

    /// Start a new block in the transcript, with one blank row before it.
    ///
    /// **One blank line between blocks, and never two.** That is the rhythm:
    /// one blank line between turns and never two, because the indent already
    /// separates the agent from Chock and blank lines do not have to. A
    /// transcript with no break at all reads as one wall, and a person cannot
    /// see where one turn ends.
    ///
    /// **The break is Chock's and an agent cannot make one.** It is a `gap`
    /// row, which carries no voice structure and no text, and the only thing
    /// that builds one is this. A blank line an agent wrote is its own content
    /// at its own indent: see `Line.gap`.
    ///
    /// **Nothing at the very top.** A blank first row would be a gap between
    /// the header band and the first thing said, which is not a break between
    /// two blocks.
    fn startBlock(self: *Ui) void {
        self.endLine();
        if (self.lines.items.len == 0) return;
        if (self.lines.items[self.lines.items.len - 1].gap) return;
        self.addLine(.{ .voice = .chock, .text = "", .gap = true });
    }

    /// One finished row that can be opened, with a copy of everything it keeps
    /// folded under it.
    ///
    /// **The body is copied and never borrowed.** It comes from an event, and
    /// an event is borrowed for the call that delivered it while this row lives
    /// for the rest of the session.
    fn sayFolded(
        self: *Ui,
        voice: Voice,
        text: []const u8,
        kind: Fold.Kind,
        body: []const u8,
    ) void {
        self.endLine();
        // **A row with nothing behind it offers no key.** A marker that opened
        // an empty body would be a key press that does nothing, which is ruled
        // out for the arrows and is no better here.
        if (body.len == 0) {
            self.say(voice, text);
            self.endLine();
            return;
        }
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, body[0..@min(body.len, kept_body_bytes)]) catch {
            self.gpa.free(kept);
            return;
        };
        self.addLine(.{
            .voice = voice,
            .text = kept,
            .fold = .{ .kind = kind, .body = held, .dropped = body.len - held.len },
        });
    }

    /// Add one finished row, dropping the oldest when there are too many.
    ///
    /// **Every index into `lines` moves when the oldest goes**, so the two this
    /// file keeps are moved here and nowhere else: the row a running call is
    /// drawn on, and the row the transcript's focus is on.
    fn addLine(self: *Ui, line: Line) void {
        if (self.lines.items.len >= kept_lines) {
            self.freeLine(self.lines.orderedRemove(0));
            if (self.running_row) |at| self.running_row = if (at == 0) null else at - 1;
            if (self.cursor) |at| self.cursor = if (at == 0) null else at - 1;
        }
        self.lines.append(self.gpa, line) catch self.freeLine(line);
    }

    fn freeLine(self: *Ui, line: Line) void {
        self.gpa.free(line.text);
        self.gpa.free(line.pinned);
        if (line.fold) |one| self.gpa.free(one.body);
    }

    /// One finished row with `right` held against its end.
    ///
    /// **The value is carried and not padded in.** A row built by padding is
    /// fixed to the width it was built at, so a narrower window wrapped the
    /// value on to a row of its own and it never came back. See `Line.pinned`.
    ///
    /// **One row and never two**, because every caller has one row's worth of
    /// words: a header, or a tool call and what it came to. A line feed in
    /// those words is a space by the time it is drawn, which is what
    /// `safeText` does with every control byte.
    fn sayPinned(self: *Ui, voice: Voice, text: []const u8, right: []const u8) void {
        self.endLine();
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, right) catch {
            self.gpa.free(kept);
            return;
        };
        self.addLine(.{ .voice = voice, .text = kept, .pinned = held });
    }

    /// One frame.
    ///
    /// **A frame that cannot be drawn is not a reason to end a session.** The
    /// words are in the log and in the transcript either way, and the transcript
    /// is written out when the display comes down however it comes down.
    /// What a person who pressed Ctrl-C once reads in the transcript.
    ///
    /// **The same two facts `interrupt.first_message` carries**, because a
    /// person who pressed once has to know both: the work carries on to a safe
    /// point, and a second press ends it now.
    pub const stopping_text = "stopping at the next safe point, and writing the session end. " ++
        "Press Ctrl-C again to stop now.";

    /// Put the fact that a stop was asked for into the transcript, once.
    ///
    /// **The signal handler's own line cannot survive a full screen display.**
    /// It writes one raw line past whatever is drawing, and `tty.noteScroll` then
    /// tells the display to paint every cell again, which is what puts the screen
    /// back and what takes that line off it. While the display was frozen between
    /// two events the line stayed up until the next one arrived; a display that
    /// repaints while it waits takes it off within a tenth of a second. So the
    /// fact belongs in the transcript, where no frame can remove it, and the
    /// handler's own line goes on being what a session with no display shows.
    ///
    /// **Chock's voice, at column zero, under the rail.** It is the harness
    /// talking to the person about the harness: see `Voice`.
    fn noteStopping(self: *Ui) void {
        if (self.said_stopping) return;
        if (!interrupt.requested()) return;
        self.said_stopping = true;
        self.startBlock();
        self.say(.chock, stopping_text);
        self.endLine();
    }

    fn draw(self: *Ui) void {
        // **A fold of the log draws nothing.** A session that ran for an hour
        // holds thousands of events, and one frame each would build and diff a
        // whole screen for every one of them while a person waits at a display
        // that is not up yet. The rows are what a replay is for, and the first
        // frame after it shows the newest of them. See `replay`.
        if (self.replaying) return;
        if (!self.running) return;
        self.noteStopping();
        if (self.paint()) return;

        // **The display said stop, so the session stops.** For a window that is
        // the close button, and a session that carried on with nothing showing
        // it would be a runaway. The terminal backend never gets here while a
        // session runs: nothing reads it then, so nothing can ask it to stop.
        // See `interrupt.requestStop`.
        self.running = false;
        interrupt.requestStop();
    }

    /// Build one frame and send it. False once the display has stopped.
    ///
    /// **The whole tree is marked dirty every time.** Phantom mounts a root once
    /// and rebuilds only what has been marked, so without this the first frame
    /// would be the only one. It is the same in both phases, which is why the
    /// message loop and the session both come through here.
    /// Take the terminal's own geometry, when it has changed since the last
    /// frame.
    ///
    /// **The display used to keep the geometry it started with for the whole
    /// run.** Every band, every wrapped row and every region width went on
    /// being measured against a window that was no longer there, and a person
    /// who made the window narrower read a transcript cut off at the old
    /// measure. Two things together did that, and neither is wrong on its own:
    ///
    /// * `phantom.tui.Session.step` follows a resize only when the caller left
    ///   `Options.size` null. `start` states it, because the tree is mounted
    ///   inside `init` and the first frame it builds has to know how much room
    ///   there is. So phantom's own branch never runs for Chock.
    /// * The flag that branch reads is set by a `SIGWINCH` handler that
    ///   `Term.enterRaw` installs. Chock takes raw mode itself, for the Ctrl-C
    ///   ownership `terminalOptions` explains, so the handler is never
    ///   installed either.
    ///
    /// **An `ioctl` per frame and not a handler of Chock's own.** A frame is
    /// drawn when something happened, and `TIOCGWINSZ` reads four numbers. A
    /// third owner of a signal, in a program where `src/interrupt.zig` owns one
    /// and phantom owns another, is a much larger thing to add.
    ///
    /// **Nothing is asked when the caller stated the size.** See `fixed_size`.
    fn followSize(self: *Ui) void {
        if (self.fixed_size) return;
        const one = self.surface.terminalSession() orelse return;
        // A device that cannot answer is a device that has gone. The frame is
        // drawn at the geometry the session already has.
        const now = one.term.size() catch return;
        if (!sizeMoved(now, one.viewport, one.dpr)) return;
        one.resize(now) catch {};
    }

    fn paint(self: *Ui) bool {
        return self.paintWaiting(0);
    }

    /// The wait one look of a keyboardless display makes.
    ///
    /// **The same tenth of a second every other look in this file takes.** Raw
    /// mode's `VTIME 1` is what bounds a look that reads a device, and
    /// `chock_core.idle.slice_ms` is the same number for the same reason, so a
    /// window repaints at the rate a terminal does and there is one number to
    /// reason about rather than three. See `Surface.stepWaiting`.
    const look_ms: u32 = @intCast(chock_core.idle.slice_ms);

    /// How long one look may wait, for a caller that was given a budget.
    ///
    /// **The shorter of the two, always.** A budget shorter than a look is a
    /// deadline that is nearly up, and a look that waited out the whole tenth
    /// of a second would expire a question after it: see `awaitAnswer`, which
    /// may not hold the session lock past the moment the request expires.
    fn lookWait(budget_ms: u64) u32 {
        return @intCast(@min(budget_ms, @as(u64, look_ms)));
    }

    /// `paint`, for a caller that is waiting and has nothing else to wait on.
    ///
    /// **Only a loop that is waiting for a person may pass a wait**, which is
    /// three of them: the message field, an open approval, and an open
    /// question. Nothing runs in the session at any of those moments, so the
    /// display cannot be pacing anything. **`draw` and `pumpStep` pass zero and
    /// must go on doing so**: both run inside a wait the session is already
    /// making, and a frame's worth of waiting on every word the model says
    /// would slow a turn to the display's frame rate. That is what
    /// `windowOptions` states zero for.
    fn paintWaiting(self: *Ui, wait_ms: u32) bool {
        // Something wrote straight at the terminal and scrolled the screen
        // under the display, so every cell the display remembers is now in the
        // wrong place. See `src/tty.zig`'s `scrolled`.
        const scrolls = tty.scrollCount();
        if (scrolls != self.seen_scrolls) {
            self.seen_scrolls = scrolls;
            self.surface.invalidate();
        }

        // **Before the frame and not after it**, so this frame is the one drawn
        // at the new geometry. See `followSize`.
        self.followSize();

        if (self.screen) |one| phantom.markNeedsBuild(one);
        const carry_on = self.surface.stepWaiting(wait_ms) catch false;
        tty.flushOut();
        return carry_on;
    }

    /// The whole screen: four regions, top to bottom.
    ///
    /// **A region is marked by a change of cell background first**, and the
    /// reason is this: phantom ships no border colour and separates surfaces by
    /// elevation, so a band is a `DecoratedBox` on `bg_dark`, `bg` or
    /// `bg_medium`, and never a drawn frame.
    ///
    /// **The approval region is absent while there is no question**, so that
    /// its arrival is itself a signal, and `approvalRows` is what answers zero
    /// for it.
    ///
    /// **The agent cannot draw there, and that is the point of the region.** An
    /// inline card would sit where agent text already goes, so a long enough
    /// message could scroll it away or put a convincing imitation beside it. A
    /// region cannot be scrolled and cannot be reached: the only agent written
    /// bytes in it are `Approval.summary`, `reason` and `detail`, each on a row
    /// of its own and each cut by `visibleLine`.
    fn view(self: *Ui, ctx: *phantom.BuildContext) phantom.Widget {
        const colors = phantom.ColorScheme.tokyoNight();
        // **How much room there is is measured here, every frame, and read
        // nowhere else.** See `resize`: the rows and the columns are what one
        // row of text really measures against the viewport phantom laid out,
        // and never a cell count multiplied by a nominal number.
        const measure = self.resize(ctx);
        const parts = split(self.rows, self.panelRows());

        var regions: std.ArrayList(phantom.Widget) = .empty;
        regions.append(ctx.arena, band(
            ctx,
            measure,
            parts.header,
            colors.bg_dark,
            self.headerRows(ctx, colors),
        )) catch {};
        // **The transcript takes the focus, so `↑ ↓` and `g` land in it and
        // nowhere else.** Focus is a security surface: a key means what the
        // focused region says it means, and never something a neighbour would
        // have done with it.
        regions.append(ctx.arena, self.middleRegions(
            ctx,
            measure,
            parts.transcript,
            colors,
        )) catch {};
        // **The raised panel, and after the transcript so it is last in the
        // focus order while a question is open.** See `Surface.focusLast`.
        //
        // **An approval, or a question from the agent, and never both.** The two
        // are separate regions with separate keys and separate state, and only
        // the rows they are drawn in are shared: see `panelRows`, and `Question`
        // for why an ask must never become an approval. The approval wins the
        // rows if both were somehow open, because it is the one with an act
        // behind it.
        if (parts.approval != 0) {
            const approving = self.approval != null;
            regions.append(ctx.arena, ctx.new(phantom.Focus{
                .child = band(
                    ctx,
                    measure,
                    parts.approval,
                    colors.bg_medium,
                    if (approving)
                        self.approvalRegion(ctx, parts.approval, colors)
                    else
                        self.questionRegion(ctx, parts.approval, colors),
                ),
                .on_key = if (approving) onApprovalKey else onQuestionKey,
                .on_focus_change = if (approving) onApprovalFocus else onQuestionFocus,
                .ctx = self,
            }).widget()) catch {};
        }
        regions.append(ctx.arena, band(
            ctx,
            measure,
            parts.input,
            colors.bg_dark,
            self.inputRows(ctx, colors),
        )) catch {};

        const screen = ctx.new(phantom.Column(.{ .children = regions.items })).widget();
        // **Around everything, and last in the dispatch order.** A key a region
        // wanted has already been taken by the time this sees it: see
        // `onSessionKey`.
        return ctx.new(phantom.KeyboardListener{
            .child = screen,
            .on_key = onSessionKey,
            .ctx = self,
        }).widget();
    }

    /// How much room the display has, measured from what phantom laid out.
    ///
    /// **Every frame, and this is the only writer of `rows`, `width` and
    /// `measure`.** A terminal's own grid is not the answer: the character grid
    /// backend draws a row per cell, and the pixel backend draws a real font at
    /// a real size whose line box is taller than a cell, so the same terminal
    /// holds fewer rows of one than of the other. Asking what a row measures,
    /// and dividing the viewport by it, gives the right answer for both without
    /// this file naming either backend.
    ///
    /// **The width is taken and never divided.** A viewport divided by a column
    /// would need a column, and only a character grid has one. The width goes
    /// through as it is and every row is measured against it: see `Room`.
    ///
    /// **The character grid comes back unchanged, which is the check.** There
    /// `Measure.height` is the reported cell height and the viewport is that
    /// height times the row count, so the division returns the terminal's own
    /// rows exactly, at any device pixel ratio, and one unit of width is one
    /// cell.
    fn resize(self: *Ui, ctx: *phantom.BuildContext) Measure {
        const measure = Measure.of(ctx);
        self.measure = measure;
        const view_now = ctx.owner.activeView() orelse return measure;
        self.rows = measure.rowsIn(view_now.metrics.size.height);
        self.width = view_now.metrics.size.width;
        return measure;
    }

    /// One region: a surface of its own, exactly `rows` rows of text tall,
    /// filled by its rows.
    ///
    /// **The `Column` inside is what makes the surface reach the edges.** A
    /// `Flex` with a bounded constraint takes the whole of it, so the box behind
    /// it is the whole band and not the width of the words on it.
    ///
    /// **The height is `rows` measured line boxes and never `rows` nominal
    /// cells.** See `Measure`: a band one nominal cell tall holding a font
    /// drawn at that same nominal size cuts the bottom off every glyph that
    /// reaches the baseline, which is the header fault.
    ///
    /// **Measured, and a terminal can flatten this.** The recess and the base
    /// are `#16161e` and `#1a1b26`, and phantom's own map to the 256 colour
    /// palette sends both to index 16, so a terminal with no truecolor shows
    /// one surface where there are two. The bands still read, because the
    /// header has its facts at the top and the input its prompt at the bottom,
    /// and the transcript's rail is a glyph rather than a colour. That is the
    /// rule: no fact may rest on colour alone.
    fn band(
        ctx: *phantom.BuildContext,
        measure: Measure,
        rows: u16,
        color: phantom.Color,
        contents: []const phantom.Widget,
    ) phantom.Widget {
        const inside = ctx.new(phantom.Column(.{ .children = contents })).widget();
        const painted = ctx.new(phantom.DecoratedBox{ .color = color, .child = inside }).widget();
        return ctx.new(phantom.SizedBox{
            .height = bandHeight(measure, rows),
            .child = painted,
        }).widget();
    }

    /// How tall a band of `rows` rows is: `rows` measured line boxes, and never
    /// `rows` nominal cells. See `band`.
    fn bandHeight(measure: Measure, rows: u16) f32 {
        return @as(f32, @floatFromInt(rows)) * measure.height();
    }

    /// The middle of the screen: the transcript, and the plan sidebar beside it
    /// when one is open.
    ///
    /// **The sidebar is beside the transcript and beside nothing else.** The
    /// header, the approval region and the input keep the whole width, because
    /// the action, the reason, the chain and the deadline never drop and a
    /// narrowed approval is exactly how they would.
    ///
    /// **The focus stays on the transcript alone.** The sidebar takes no keys,
    /// so `Tab` moves between the same two regions it always did. See
    /// `planRows`.
    ///
    /// **The row is built whether or not there is a sidebar in it**, and that
    /// is not tidiness. Phantom mounts an element for each place in the tree,
    /// so wrapping the transcript in a row only while the sidebar is open
    /// remounts the `Focus` around it on the very keystroke that opened it. The
    /// transcript would lose the keyboard as the sidebar arrived, and the key
    /// that closes it again would reach nothing.
    ///
    /// **The transcript is `Expanded` and the sidebar is a fixed width.** The
    /// sidebar is stated in characters and the transcript is what is left, so
    /// the flex hands the transcript exactly the width `transcriptBandRoom`
    /// worked out. A closed sidebar is zero wide and the transcript is the
    /// whole row, which is the layout this file had before there was one.
    fn middleRegions(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        // **The transcript takes the focus, so `↑ ↓` and `g` land in it and
        // nowhere else.** Focus is a security surface: a key means what the
        // focused region says it means, and never something a neighbour would
        // have done with it.
        const focused = ctx.new(phantom.Focus{
            .child = self.transcriptBand(ctx, measure, rows, colors),
            .on_key = onTranscriptKey,
            .on_focus_change = onTranscriptFocus,
            .ctx = self,
        }).widget();

        const side = self.sidebarWidth();
        const beside = if (side > 0) band(
            ctx,
            measure,
            rows,
            // A recess, which is what a region that never scrolls gets. The
            // header and the input are the same, and the raised panel is kept
            // for the approval, whose arrival is meant to read as a change.
            colors.bg_dark,
            self.sidebarRows(ctx, rows, colors),
        ) else plainRow(ctx, "", colors.fg);

        const both = ctx.newSlice(phantom.Widget, &.{
            ctx.new(phantom.Expanded(.{ .child = focused })).widget(),
            ctx.new(phantom.SizedBox{ .width = side, .child = beside }).widget(),
        });
        // **The row is given its height, because a flex fills the axis it does
        // not lay out along.** Without this the middle of the screen takes the
        // whole display and the input band is drawn under it.
        return ctx.new(phantom.SizedBox{
            .height = bandHeight(measure, rows),
            .child = ctx.new(phantom.Row(.{ .children = both })).widget(),
        }).widget();
    }

    /// The rows of the plan sidebar, cut to the region.
    ///
    /// **A step's subject is the agent's own text**, and this is a region the
    /// agent cannot otherwise draw in. It is admitted on the same terms the
    /// approval region admits `summary`, `reason` and `detail`: one field to a
    /// row, and every row through `visibleLine`, so a control byte becomes a
    /// space and a long subject stops at the edge rather than wrapping back
    /// under the transcript.
    fn sidebarRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        const said = planRows(ctx.arena, self.plan, rows) catch return &.{};
        for (said) |one| {
            lines.add(ctx.arena, row(
                ctx,
                self.measure,
                visibleLine(ctx.arena, one.text, self.sidebarRoom()) catch "",
                switch (one.tone) {
                    .title => colors.blue_light,
                    // The third signal, and never the only one: the word
                    // `statusWord` writes carries the status on its own.
                    .now => colors.green,
                    .step => colors.fg,
                    .aside => colors.fg_muted,
                },
            ));
        }
        return lines.items();
    }

    /// The transcript region, with a pane over it when one is open.
    ///
    /// **A `Stack`, so the pane is over the transcript and inside it.** The
    /// band under it is the first child and therefore sizes the stack, and the
    /// pane is pinned to all four of its edges, so the pane is exactly the
    /// region and never a row taller or shorter than it. Nothing about the
    /// transcript below has to know a pane exists, and nothing the pane does
    /// can change how many rows the transcript was given.
    ///
    /// **The rows under it are still built.** A pane is a surface over the
    /// session and not a mode the session goes into, so the transcript is
    /// exactly where it was when the pane closes.
    fn transcriptBand(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const under = band(
            ctx,
            measure,
            rows,
            colors.bg,
            self.transcriptRows(ctx, measure, rows, colors),
        );
        const over = self.paneOver(ctx, rows, colors) orelse return under;
        return ctx.new(phantom.Stack{
            .children = ctx.newSlice(phantom.Widget, &.{ under, over }),
        }).widget();
    }

    /// The open pane, pinned over the whole transcript region, or null when
    /// there is none.
    ///
    /// **Pinned rather than sized.** `phantom.Positioned` with all four edges
    /// given makes the pane exactly the box the stack is, whatever that box
    /// measures, so no row count is multiplied out a second time here.
    ///
    /// **A raised surface, which is how a region says it changed.** Phantom
    /// ships no border colour and separates surfaces by elevation, so the pane
    /// is `bg_medium` over the transcript's `bg` and needs no frame.
    fn paneOver(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) ?phantom.Widget {
        if (self.pane == null) return null;
        const contents = self.paneRows(ctx, rows, colors);
        const inside = ctx.new(phantom.Column(.{ .children = contents })).widget();
        const painted = ctx.new(phantom.DecoratedBox{
            .color = colors.bg_medium,
            .child = inside,
        }).widget();
        return ctx.new(phantom.Positioned{
            .top = 0,
            .right = 0,
            .bottom = 0,
            .left = 0,
            .child = painted,
        }).widget();
    }

    /// The rows of the open pane: its title, as much of it as there is room
    /// for, and what is left over.
    ///
    /// **The title and the count are Chock's, and they never drop.** A person
    /// on a screen with three rows still learns what the pane is and that there
    /// is more of it, because a pane that silently showed its first three rows
    /// is exactly the fault this replaced.
    ///
    /// **The count is at the bottom and says a number.** A row saying how many
    /// are left is a fact; a cut off sentence is not, and neither is a gap. That
    /// is the same rule `ruleRow` follows for the transcript.
    fn paneRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        if (self.pane == null) return &.{};
        const pane = &self.pane.?;
        const all = switch (pane.kind) {
            .keys => helpRows(ctx.arena) catch return &.{},
        };
        const total: u16 = @intCast(@min(all.len, std.math.maxInt(u16)));

        var lines = Rows{ .left = rows };
        // The title takes a row and so does the count, so the pane's own text
        // is given what is left. A region with no room for both keeps the
        // title, because the title is what says a pane is there at all.
        const room = rows -| 2;
        pane.hold(room, total);

        lines.add(ctx.arena, self.bandRow(ctx, switch (pane.kind) {
            .keys => " keys",
        }, colors.blue_light));

        var index: u16 = pane.at;
        while (index < total and index < pane.at + room) : (index += 1) {
            lines.add(ctx.arena, self.bandRow(
                ctx,
                std.fmt.allocPrint(ctx.arena, " {s}", .{all[index]}) catch "",
                colors.fg,
            ));
        }

        const left = total -| (pane.at + room);
        lines.add(ctx.arena, self.bandRow(ctx, if (left == 0)
            " Esc closes this"
        else
            std.fmt.allocPrint(ctx.arena, " {d} rows below. Esc closes this.", .{
                left,
            }) catch " Esc closes this", colors.fg_muted));
        return lines.items();
    }

    /// The header: the project, how its workspace is made, what is answering,
    /// and every sandbox layer.
    ///
    /// **Never scrolls and the agent cannot draw here**, which is half of why it
    /// is a region rather than a line in the transcript.
    ///
    /// **The layers are why this band is worth a row.** See `headerPieces`,
    /// which decides what fits, and `Layer.State`, which decides what each one
    /// says.
    fn headerRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var said: std.ArrayList(HeaderPiece) = .empty;
        headerPieces(ctx.arena, self.facts, self.screenRoom(), &said) catch {};

        var pieces: std.ArrayList(phantom.Widget) = .empty;
        for (said.items) |one| {
            pieces.append(ctx.arena, row(ctx, self.measure, one.text, switch (one.tone) {
                .name => colors.fg,
                .context => colors.fg_muted,
                // The third signal, and never the only one: the glyph and the
                // word carry the fact on their own. See `Layer.State`.
                .on => colors.green,
                .off => colors.red,
            })) catch {};
        }

        const line = ctx.new(phantom.Row(.{ .children = pieces.items })).widget();
        return ctx.newSlice(phantom.Widget, &.{line});
    }

    /// The transcript: the session, folded from events, newest at the bottom.
    ///
    /// **Chock's rows carry the rail at column 0 and the agent's are indented
    /// past it.** That is the security property, and it lives here because this
    /// is the one region agent text may reach at all. See `Voice`.
    fn transcriptRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        var room = rows;

        // **The lists sit above the input band**, which is where the owner
        // asked for them, so they take their rows from the bottom of the
        // transcript rather than from a pane of their own. See
        // `openCompletions` and `openPicker`.
        var slots: [Command.all.len]Command = undefined;
        const all_listed = self.openCompletions(&slots);
        const all_offered = self.picker orelse &[_]Resumable{};
        // **Cut to the rows there are, and not only counted against them.** A
        // list longer than the whole transcript used to take every row it asked
        // for and draw the rest of them past the band. See `Rows`.
        const taken: u16 = @intCast(@min(all_listed.len + all_offered.len, room));
        const listed = all_listed[0..@min(all_listed.len, taken)];
        // **The picker follows the choice.** A list of sessions longer than the
        // transcript is drawn from wherever the chosen one is, because a list
        // that cannot show what is chosen is a list nobody can answer.
        const seats = taken - listed.len;
        const first = if (self.picked < seats) 0 else self.picked - seats + 1;
        const offered = all_offered[@min(first, all_offered.len)..][0..seats];
        room -= taken;

        // **Only while there is a row left for it.** The rule says how much is
        // above and the rows themselves are what a person came to read.
        if (self.showsRule() and room != 0) {
            lines.add(ctx.arena, self.ruleRow(ctx, colors));
            room -= 1;
        }

        // **The row still being written is only shown at the bottom.** Scrolled
        // back, a person is reading history and the words arriving now belong
        // where they will land, which is out of view.
        const open: u16 = if (self.pending.items.len != 0 and self.scroll_back == 0) 1 else 0;
        const shown = self.visibleRows(ctx.arena, room -| open);

        // Blank rows go above, so the newest row sits against the input band
        // and the whole transcript does not climb the screen as it fills.
        var blank: u16 = room -| (@as(u16, @intCast(shown.len)) + open);
        while (blank > 0) : (blank -= 1) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }
        for (shown) |line| {
            lines.add(ctx.arena, self.voicedRow(ctx, measure, line, colors));
        }
        if (open != 0) {
            lines.add(ctx.arena, self.voicedRow(ctx, measure, .{
                .voice = self.pending_voice,
                .text = self.pending.items,
            }, colors));
        }
        for (self.completionRows(ctx, listed, colors)) |one| {
            lines.add(ctx.arena, one);
        }
        for (offered, 0..) |one, index| {
            lines.add(ctx.arena, self.pickerRow(ctx, one, first + index, colors));
        }
        return lines.items();
    }

    /// The approval region: the question, and the keys that answer it.
    ///
    /// **The order inside is this file's.** The order of action, chain, reason
    /// and diff inside the region is open. That it is a region is not. What is
    /// not open is what may never drop, and those four are the action, the
    /// reason, the chain, and the deadline. Each of them is on a row of its own
    /// at every width.
    ///
    /// **The first and last rows are Chock's own.** The action and the countdown
    /// at the top, the keys at the bottom, and the agent's words only in
    /// between: see `Approval`.
    fn approvalRegion(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        const one = self.approval orelse return &.{};
        var lines = Rows{ .left = rows };

        // **The keys row is reserved before any other row is built.** A region
        // too short to hold everything loses a middle row and never the row
        // that says how to answer, and a region with one row is that row alone.
        // See `Rows`: a row built past the end is covered by the band below and
        // reads as a row cut through.
        if (rows == 0) return &.{};
        var room = rows - 1;

        // **The word `APPROVAL`, the action, and a number that counts down.**
        // Three signals that are not colour: the word, the number, and the
        // region itself.
        if (room != 0) {
            room -= 1;
            const left = countdownText(ctx.arena, one.left_ms) catch "";
            lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                ctx.arena,
                " APPROVAL  {s}   {s}",
                .{ one.action, left },
            ) catch " APPROVAL", colors.blue_light));
        }
        switch (one.view) {
            // **In the order that may never drop.** The action, the reason, the
            // chain, and the deadline never drop: the action and the deadline
            // are the row above, and the chain and the reason are the first two
            // here. The summary and the size of the effect are what a region
            // too short for six rows gives up.
            .question => {
                const middle = [_][]const u8{
                    std.fmt.allocPrint(ctx.arena, " {s}  depth {d}", .{
                        one.chain,
                        one.depth,
                    }) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   \"{s}\"", .{one.reason}) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   {s}", .{one.summary}) catch " ",
                    if (one.review.len != 0)
                        std.fmt.allocPrint(ctx.arena, "   review: {s}", .{one.review}) catch " "
                    else
                        std.fmt.allocPrint(ctx.arena, "   {d} bytes of effect. [d] shows them.", .{
                            one.detail.len,
                        }) catch " ",
                };
                const tones = [middle.len]phantom.Color{
                    colors.fg_muted,
                    colors.fg,
                    colors.fg,
                    colors.fg_muted,
                };
                for (middle, tones) |text, tone| {
                    if (room == 0) break;
                    room -= 1;
                    lines.add(ctx.arena, self.regionRow(ctx, text, tone));
                }
            },
            // **The effect at length, and answering stays available from inside
            // it.** The keys row below is what keeps that true.
            .diff => {
                var rest = one.detail;
                while (room > 0) : (room -= 1) {
                    const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
                    lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                        ctx.arena,
                        "   {s}",
                        .{rest[0..at]},
                    ) catch " ", colors.fg));
                    if (at == rest.len) break;
                    rest = rest[at + 1 ..];
                }
            },
            // **The spawn chain in full**, which is what `w` asks for: each
            // parent and the reason it gave.
            .why => {
                const middle = [_][]const u8{
                    std.fmt.allocPrint(ctx.arena, " {s}  depth {d}", .{
                        one.chain,
                        one.depth,
                    }) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   \"{s}\"", .{one.reason}) catch " ",
                };
                for (middle) |text| {
                    if (room == 0) break;
                    room -= 1;
                    lines.add(ctx.arena, self.regionRow(ctx, text, colors.fg));
                }
            },
        }

        // Everything left is blank, so the keys sit at the bottom of the region
        // and never move when a view changes.
        while (lines.left > 1) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }
        lines.add(ctx.arena, self.regionRow(
            ctx,
            if (self.answersKeys())
                approvalKeys(self.screenRoom())
            else
                elsewhereText(ctx.arena, self.current_session, self.screenRoom()),
            colors.blue_light,
        ));
        return lines.items();
    }

    /// The question region: Chock's own header, the model's words behind a
    /// gutter, the answer line, and the keys.
    ///
    /// ## The gutter is the security property of this region
    ///
    /// **The question is written by the model, so it is untrusted text put in
    /// front of a person**, and the fault to stop is a question that reads as
    /// Chock's own words: "chock: your credential expired, paste it here" would
    /// be a phishing surface inside the user's own terminal. Two things stop it,
    /// and both are the same two `chock_core.ask.promptText` uses at the bare
    /// prompt:
    ///
    /// * **Every row of the model's words begins with
    ///   `chock_core.ask.question_marker`**, so no byte the model chose can
    ///   start a row of this region. Chock's own three rows are the only ones
    ///   that reach column zero.
    /// * **Every byte a terminal reads as an instruction is replaced.**
    ///   `regionRow` puts every row through `visibleLine`, which turns a control
    ///   byte into a space, so a cursor move cannot repaint the header and a
    ///   carriage return cannot overwrite a marker. It has the same honest limit
    ///   it has for a diff: it does not cover the characters that reverse a
    ///   line's direction, or a word that reads like another word.
    ///
    /// **This is easier to get wrong in a region than in a line printer**, and
    /// the reason is that a row here is built by `allocPrint` from more than one
    /// piece. So the model's words appear in exactly two of the format strings
    /// below, and each of those starts with the marker.
    ///
    /// ## It never says an act needs permission
    ///
    /// The keys row carries "Answering allows nothing" at every width, because
    /// the region above this one is an approval and looks very like it. See
    /// `Question`.
    fn questionRegion(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        const one = self.question orelse return &.{};
        var lines = Rows{ .left = rows };

        if (rows == 0) return &.{};
        // **The keys row and the answer line are reserved before anything
        // else.** A region too short to hold the whole question loses a line of
        // the question, and never the row a person types on or the row that says
        // what the keys do. See `Rows`.
        if (rows < 3) return &.{};
        var room = rows - 3;

        // Chock's own row, at column zero, and it says whose words follow. It
        // names no act: see `Question`.
        const left = countdownText(ctx.arena, one.left_ms) catch "";
        lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
            ctx.arena,
            " QUESTION from {s}   {s}",
            .{ if (one.agent_kind.len == 0) "the agent" else one.agent_kind, left },
        ) catch " QUESTION", colors.blue_light));

        // The model's own words, one row each, every one behind the gutter.
        var body = std.mem.splitScalar(u8, one.text, '\n');
        while (body.next()) |line| {
            if (room == 0) break;
            room -= 1;
            lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                ctx.arena,
                chock_core.ask.question_marker ++ "{s}",
                .{line},
            ) catch chock_core.ask.question_marker, colors.fg));
        }

        // The list, if the model offered one, numbered by Chock and behind the
        // same gutter. **A number is a shortcut and never a wall**: a person
        // types their own words whenever they like, which is what
        // `chock_core.ask.chosen` already keeps true at the bare prompt.
        if (one.options.len != 0 and room != 0) {
            room -= 1;
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
            for (one.options, 1..) |option, number| {
                if (room == 0) break;
                room -= 1;
                lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                    ctx.arena,
                    chock_core.ask.question_marker ++ "{d}) {s}",
                    .{ number, option },
                ) catch chock_core.ask.question_marker, colors.fg_muted));
            }
        }

        // Everything left is blank, so the answer line and the keys sit at the
        // bottom of the region and never move as a person types.
        while (lines.left > 2) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }

        // The answer line. **The person's own bytes**, after Chock's own prompt,
        // and put through `visibleLine` like every other row: a paste can carry
        // anything.
        lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
            ctx.arena,
            answer_prompt ++ "{s}\u{2588}",
            .{self.question_typed[0..self.question_filled]},
        ) catch answer_prompt, colors.fg));

        lines.add(ctx.arena, self.regionRow(
            ctx,
            if (self.answersKeys())
                questionKeys(self.screenRoom(), one.options.len != 0)
            else
                question_unanswerable,
            colors.blue_light,
        ));
        return lines.items();
    }

    /// One row of the approval region, cut to the screen.
    ///
    /// **Every row goes through `visibleLine`**, because three of the fields on
    /// it are the agent's own words: a control byte becomes a space and a long
    /// line stops at the edge rather than wrapping back to column 0.
    fn regionRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return row(
            ctx,
            self.measure,
            visibleLine(ctx.arena, text, self.screenRoom()) catch "",
            color,
        );
    }

    /// One row drawn inside the transcript's own band, cut to that band.
    ///
    /// **The transcript's band and not the display.** The rule, the two lists
    /// and the pane are all drawn inside the transcript region, and with the
    /// plan sidebar open that region is narrower than the screen. A row cut to
    /// the screen is painted over by the sidebar beside it, which loses the end
    /// of the row and shows nothing to say it went.
    ///
    /// **One place, so the four cannot answer differently.** Each of them used
    /// to cut against the screen on its own line, which is four chances to get
    /// the same answer wrong.
    fn bandRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return row(
            ctx,
            self.measure,
            visibleLine(ctx.arena, text, self.transcriptBandRoom()) catch "",
            color,
        );
    }

    /// One session the picker is offering.
    ///
    /// **A refused row says so on itself**, in the colour a refusal gets and
    /// with the reason spelled out beside it, so the fact does not rest on the
    /// colour.
    fn pickerRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        one: Resumable,
        index: usize,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const chosen = index == self.picked;
        const words = if (one.refusal.len == 0)
            std.fmt.allocPrint(ctx.arena, "{s} {s}", .{
                if (chosen) "\u{25b8}" else " ",
                one.words,
            }) catch one.words
        else
            std.fmt.allocPrint(ctx.arena, "{s} {s}  {s}", .{
                if (chosen) "\u{25b8}" else " ",
                one.words,
                one.refusal,
            }) catch one.words;

        return self.bandRow(ctx, words, if (one.refusal.len != 0)
            colors.red
        else if (chosen)
            colors.blue_light
        else
            colors.fg_muted);
    }

    /// The rule that says what is above, and that the transcript has the focus.
    ///
    /// **A rule and not a gap.** A count and a line, because a gap or an
    /// ellipsis reads as loss and nothing here is lost. The whole session is in
    /// the log and in the transcript.
    ///
    /// **Accent when the region holds the focus.** `fg.accent` has two
    /// meanings, Chock's rail and focus, so a region that has the keyboard says
    /// so in the colour that already means that. It is not the only signal: the
    /// rule appears at all only when the region is focused or scrolled.
    fn ruleRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const words = std.fmt.allocPrint(
            ctx.arena,
            "\u{2500}\u{2500} {d} rows above. The log keeps them. \u{2500}\u{2500}",
            .{self.scroll_back},
        ) catch "\u{2500}\u{2500}";
        return self.bandRow(ctx, words, if (self.transcript_focused)
            colors.blue_light
        else
            colors.fg_dim);
    }

    /// The input band: what you type, and the prompt it is typed after.
    ///
    /// **The prompt is always there and the field is not.** A person reads the
    /// band as theirs either way, and the field appears only while a message is
    /// wanted: see `askForMessage`.
    fn inputRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var pieces: std.ArrayList(phantom.Widget) = .empty;
        // **The prompt says whether this region has the keyboard.** Accent is
        // what focus gets, and dim is what something secondary gets. Focus has
        // to be visible, and this and the transcript's rule row are the two
        // places it is.
        pieces.append(ctx.arena, plainRow(
            ctx,
            " > ",
            if (self.transcript_focused) colors.fg_dim else colors.blue_light,
        )) catch {};

        if (self.phase == .message) {
            // **A `phantom.TextField`, so the message is typed in the interface
            // and not on a line before it.** `phantom.KeyboardListener` around
            // it is what gives Enter a meaning: the field deliberately leaves
            // that key alone, because it does not own what the text is for.
            // No size, for the reason `row` gives.
            const field = ctx.new(phantom.TextField{
                .color = colors.fg,
                .caret_color = colors.blue_light,
                .on_change = onTyped,
                .ctx = self,
            });
            pieces.append(ctx.arena, ctx.new(phantom.KeyboardListener{
                .child = field.widget(),
                .on_key = onMessageKey,
                .ctx = self,
            }).widget()) catch {};
        }

        const line = ctx.new(phantom.Row(.{ .children = pieces.items })).widget();
        return ctx.newSlice(phantom.Widget, &.{line});
    }

    /// The commands that match what is typed, or none.
    ///
    /// **Open only while what is typed is the start of one.** That is what makes
    /// the rule in `commandOf` visible rather than folklore: a person typing a
    /// path watches the list close and can see the line is a message.
    fn openCompletions(self: *const Ui, into: []Command) []const Command {
        if (self.phase != .message) return into[0..0];
        return completions(self.typed.items, into);
    }

    /// The rows of the completion list, drawn above the input band.
    fn completionRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        shown: []const Command,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var rows: std.ArrayList(phantom.Widget) = .empty;
        for (shown, 0..) |one, index| {
            const chosen = index == self.completion_selected;
            const words = std.fmt.allocPrint(ctx.arena, "{s} {s: <8}  {s}", .{
                // The mark, so the choice reads on a screen with no colour.
                if (chosen) "\u{25b8}" else " ",
                one.typed(),
                one.does(),
            }) catch one.typed();
            rows.append(ctx.arena, self.bandRow(
                ctx,
                words,
                if (chosen) colors.blue_light else colors.fg_muted,
            )) catch {};
        }
        return rows.items;
    }

    /// Keep what the field holds. The slice is borrowed for the call only, so
    /// it is copied.
    fn onTyped(context: *anyopaque, text: []const u8) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.completion_selected = 0;
        self.typed.clearRetainingCapacity();
        // A message that could not be kept is a message that stays as it was,
        // which the person sees on screen and can correct.
        self.typed.appendSlice(self.gpa, text) catch {};
    }

    /// Enter means "this is the message". Every other key is left alone, so the
    /// field keeps the ones it wants and the focus rules keep Tab.
    fn onMessageKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        if (event.keysym != .enter) return false;
        const self: *Ui = @ptrCast(@alignCast(context));

        // **Enter on the picker takes the session that is chosen**, or says why
        // it cannot be taken and leaves the picker open so another can be.
        if (self.picker != null) {
            self.takePicked();
            return true;
        }

        // **Enter on an open list takes what is chosen.** The line becomes that
        // command in full, so a person who typed `/pl` and pressed Enter runs
        // `/plan` rather than sending two letters to the model.
        var slots: [Command.all.len]Command = undefined;
        const listed = self.openCompletions(&slots);
        if (listed.len != 0) {
            const chosen = listed[@min(self.completion_selected, listed.len - 1)];
            self.typed.clearRetainingCapacity();
            self.typed.appendSlice(self.gpa, chosen.typed()) catch {};
        }

        self.submitted = true;
        return true;
    }

    /// Every row of the transcript as it is drawn, oldest first.
    ///
    /// **A row is not a `Line`.** A row that has been opened puts its body
    /// underneath it, and those body rows scroll, are counted, and are cut like
    /// any other. Nothing here is kept: `Line.fold.open` is the state and this
    /// is what that state looks like.
    ///
    /// **Every body row is in the agent's voice**, whichever voice its head was
    /// in, because a body is always agent supplied text. See `Fold`.
    ///
    /// **A row that is too long is wrapped and never cut.** Every row of a
    /// wrapped line keeps its own voice, so every continuation of an agent line
    /// carries the agent's indent and none of them can reach column 0, which is
    /// the voice rule. See `wrapText` and `Voice`.
    fn showRows(self: *const Ui, arena: std.mem.Allocator) []const Shown {
        var out: std.ArrayList(Shown) = .empty;
        for (self.lines.items, 0..) |line, at| {
            const fold = line.fold;
            if (line.gap) {
                out.append(arena, .{ .voice = line.voice, .text = "", .gap = true }) catch
                    return out.items;
                continue;
            }
            // **The marker goes on the first row of a wrapped line**, where the
            // eye that has just read the head of the block finds it, and never
            // repeated down the continuations. The right hand value the row
            // carries goes to the same place, for the same reason.
            const head = wrapText(arena, line.text, self.roomFor(line.voice)) catch
                return out.items;
            for (head, 0..) |words, part| {
                out.append(arena, .{
                    .voice = line.voice,
                    .text = words,
                    .pinned = if (part == 0) line.pinned else "",
                    .fold_at = if (fold != null and part == 0) at else null,
                    .open = if (fold) |one| one.open else false,
                }) catch return out.items;
            }
            const one = fold orelse continue;
            if (!one.open) continue;

            var rest = one.body;
            var drawn: usize = 0;
            while (rest.len != 0 and drawn < open_body_rows) {
                const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
                const body = wrapText(arena, rest[0..end], self.roomFor(.agent)) catch
                    return out.items;
                for (body) |words| {
                    out.append(arena, .{ .voice = .agent, .text = words }) catch
                        return out.items;
                }
                drawn += 1;
                if (end == rest.len) {
                    rest = rest[end..];
                    break;
                }
                rest = rest[end + 1 ..];
            }
            // **Never silence**, which is the rule for a truncated result. At
            // the agent's indent, because this row stands among the agent's own
            // bytes.
            if (rest.len + one.dropped != 0) {
                const more = std.fmt.allocPrint(
                    arena,
                    "\u{2026} {d} bytes more, in the log",
                    .{rest.len + one.dropped},
                ) catch "\u{2026} more, in the log";
                out.append(arena, .{ .voice = .agent, .text = more }) catch return out.items;
            }
        }
        return out.items;
    }

    /// How many rows the transcript has to draw.
    ///
    /// **Built rather than counted a second way.** A row is no longer one line:
    /// a line that is too long wraps and an open fold puts its body underneath,
    /// and a second walk that worked all of that out again would be a second
    /// answer that can drift from the drawn one. A drift here is a scroll that
    /// stops short of the oldest row or runs past the newest, which is the sort
    /// of fault nobody reports and everybody feels.
    fn shownCount(self: *const Ui) usize {
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        return self.showRows(arena_state.allocator()).len;
    }

    /// The last `count` rows of the transcript, oldest first.
    fn visibleRows(self: *const Ui, arena: std.mem.Allocator, count: u16) []const Shown {
        const all = self.showRows(arena);
        const back = @min(self.scroll_back, all.len -| count);
        const end = all.len - back;
        const from = end - @min(end, count);
        return all[from..end];
    }

    /// How far back the transcript can be scrolled: enough to bring the oldest
    /// row it still keeps into view, and not one row further.
    ///
    /// **Bounded by what is kept, not by what the session said.** Older rows are
    /// dropped once there are `kept_lines` of them, and the whole session is in
    /// the transcript and in the log either way. See `kept_lines`.
    fn maxScrollBack(self: *const Ui) usize {
        // **The rule row is always counted, drawn or not.** It is drawn from
        // the first press onward, so counting it only when it is there would
        // move the ceiling by one the moment a person reached for it, and a
        // ceiling that shifts under a held key is a ceiling nothing can rest
        // against. See `showsRule`.
        const parts = split(self.rows, self.panelRows());
        const room = parts.transcript -| 1;
        return self.shownCount() -| room;
    }

    /// Whether the rule that says how much is above is drawn.
    ///
    /// **On when the transcript has focus, and on while it is scrolled.** The
    /// first is what makes focus visible, and focus has to be visible because
    /// it decides where a keystroke lands. The second is a rule saying what is
    /// above, rather than a gap or an ellipsis, because those read as loss.
    fn showsRule(self: *const Ui) bool {
        return self.transcript_focused or self.scroll_back != 0;
    }

    /// Move the transcript by `rows`, positive for older. Clamped at both ends,
    /// so a held key stops at the oldest row rather than running past it.
    fn scrollBy(self: *Ui, rows: i32) void {
        const most = self.maxScrollBack();
        const now: i64 = @intCast(self.scroll_back);
        const moved = std.math.clamp(now + rows, 0, @as(i64, @intCast(most)));
        self.scroll_back = @intCast(moved);
    }

    /// Which way the transcript's own focus moves.
    const Step = enum { older, newer };

    /// Move the transcript's focus to the next thing that can be opened.
    ///
    /// **The arrows belong to the session and `Space` to the focused thing, and
    /// nothing says how a row comes to be focused.** This is that answer:
    /// inside the transcript, and only while the transcript holds the keyboard,
    /// the arrows step between the rows `Space` can act on, and the view
    /// follows. Every other region still scrolls by a row, which is where the
    /// arrows land while a person is typing: see `onSessionKey`.
    ///
    /// **A transcript with nothing to open scrolls instead**, so the arrows are
    /// never a key that does nothing.
    fn stepCursor(self: *Ui, step: Step) void {
        if (self.foldCount() == 0) {
            self.scrollBy(if (step == .older) 1 else -1);
            return;
        }

        const at = self.cursor orelse {
            // Nothing is focused yet, so the first press takes the newest row
            // that can be opened, whichever arrow it was: that is the row the
            // eye is already on, because the newest thing is lowest.
            self.cursor = self.nextFold(self.lines.items.len, .older);
            self.showCursor();
            return;
        };
        self.cursor = self.nextFold(at, step) orelse at;
        self.showCursor();
    }

    /// How many rows of the transcript can be opened at all.
    fn foldCount(self: *const Ui) usize {
        var found: usize = 0;
        for (self.lines.items) |line| {
            if (line.fold != null) found += 1;
        }
        return found;
    }

    /// The nearest row before or after `from` that can be opened, or null when
    /// there is none that way.
    fn nextFold(self: *const Ui, from: usize, step: Step) ?usize {
        if (step == .older) {
            var at = @min(from, self.lines.items.len);
            while (at > 0) {
                at -= 1;
                if (self.lines.items[at].fold != null) return at;
            }
            return null;
        }
        var at = from + 1;
        while (at < self.lines.items.len) : (at += 1) {
            if (self.lines.items[at].fold != null) return at;
        }
        return null;
    }

    /// Scroll so the focused row is on the screen.
    ///
    /// **The focus decides the scroll and never the other way round.** A row
    /// that can be opened but cannot be seen is a key press with nothing to
    /// show for it.
    fn showCursor(self: *Ui) void {
        const at = self.cursor orelse return;
        const parts = split(self.rows, self.panelRows());
        const room: usize = parts.transcript -| 1;
        if (room == 0) return;

        // How many drawn rows there are from the focused one to the newest.
        //
        // **Read off the rows that are really drawn**, for the reason
        // `shownCount` gives: a line is not a row any more, so a walk that
        // worked the count out a second way would be a second answer.
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const all = self.showRows(arena_state.allocator());
        var first: ?usize = null;
        for (all, 0..) |one, index| {
            if (one.fold_at != null and one.fold_at.? == at) {
                first = index;
                break;
            }
        }
        const below = all.len - (first orelse return);
        self.scroll_back = @min(below -| room, self.maxScrollBack());
    }

    /// Open or close the focused row, which is what `Space` does.
    fn toggleFocused(self: *Ui) void {
        const at = self.cursor orelse return;
        if (at >= self.lines.items.len) return;
        if (self.lines.items[at].fold == null) return;
        self.lines.items[at].fold.?.open = !self.lines.items[at].fold.?.open;
        self.showCursor();
    }

    /// Every key the transcript region takes while it holds the focus.
    ///
    /// **Only while it holds the focus**, which is the rule and the reason `g`
    /// is safe as one letter: with the field focused, `g` is a letter a person
    /// is typing, and it never reaches here.
    fn onTranscriptKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        // **An open pane takes the keys of the region it is over, and only
        // those.** The pane is drawn inside this region, so a key that already
        // belongs to this region is the pane's while it is open: the arrows
        // read it instead of scrolling the transcript under it. Nothing outside
        // the region changes, so `Tab` still leaves, and the approval region
        // still takes its own keys.
        if (self.pane != null and self.onPaneKey(event)) return true;
        switch (event.keysym) {
            .up => {
                self.stepCursor(.older);
                return true;
            },
            .down => {
                self.stepCursor(.newer);
                return true;
            },
            else => {
                const typed = event.text orelse return false;
                // `Space`: expand or collapse the focused thing, which is a
                // tool result, a reasoning block, a compaction or a subagent.
                // It is answered here and never in `onSessionKey`, so a space
                // typed into the message field stays a space: this handler runs
                // only while the transcript holds the focus.
                if (std.mem.eql(u8, typed, " ")) {
                    self.toggleFocused();
                    return true;
                }
                // `g`: go to the newest event, after scrolling back.
                if (std.mem.eql(u8, typed, "g")) {
                    self.scroll_back = 0;
                    self.cursor = null;
                    return true;
                }
                // `p`: the plan, beside the transcript. Answered here for the
                // reason `Space` and `g` are, so a `p` typed into the message
                // field stays a letter of the message.
                if (std.mem.eql(u8, typed, "p")) {
                    self.togglePlan();
                    return true;
                }
                // `?`: every key, and every key has to be reachable.
                //
                // **In a pane**: `?` shows every key in a pane, because a pane
                // is a thing a person can read all of, and rows written into
                // the transcript are not: the end of a long answer is off the
                // bottom of a short screen the moment it arrives. It also keeps
                // the keys out of the session's own record. See `Pane`.
                if (std.mem.eql(u8, typed, "?")) {
                    self.openHelp();
                    return true;
                }
                return false;
            },
        }
    }

    /// Every key the open pane takes, and false for the ones it does not.
    ///
    /// **The pane is not a mode.** It answers the arrows and the two keys that
    /// close it, and refuses everything else, so `Tab` still moves the focus
    /// out of the region and `g` and `Space` still reach the transcript under
    /// it. A pane that swallowed every key would be a place a person can get
    /// stuck in.
    fn onPaneKey(self: *Ui, event: phantom.input.KeyEvent) bool {
        if (self.pane == null) return false;
        const pane = &self.pane.?;
        const room = split(self.rows, self.panelRows()).transcript -| 2;
        // The row count the pane is scrolling through. Building the rows is the
        // only way to count them, and it is a few dozen short strings.
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const all = switch (pane.kind) {
            .keys => helpRows(arena_state.allocator()) catch return false,
        };
        const total: u16 = @intCast(@min(all.len, std.math.maxInt(u16)));

        switch (event.keysym) {
            .up => {
                pane.move(-1, room, total);
                return true;
            },
            .down => {
                pane.move(1, room, total);
                return true;
            },
            .escape => {
                self.pane = null;
                return true;
            },
            else => {
                const typed = event.text orelse return false;
                if (std.mem.eql(u8, typed, "?")) {
                    self.pane = null;
                    return true;
                }
                return false;
            },
        }
    }

    fn onTranscriptFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.transcript_focused = focused;
    }

    /// The four keys that answer an approval.
    ///
    /// **Only while the region holds the focus**, which is what the `Focus`
    /// widget around it gives, and that is a security property: `y` means
    /// approve only there, because a keystroke aimed at the transcript could
    /// otherwise answer a request that appeared a moment earlier.
    ///
    /// **`Enter` and `Esc` do nothing, deliberately.** They are not listed and
    /// they are not defaults, so they fall through to the session's own
    /// listener, which does nothing with either. A user who is leaning on Enter
    /// to clear a build log must not approve a push by accident, and an
    /// approval is not dismissable: refusing is an answer, and ignoring is not.
    ///
    /// **Nothing is answered while the settle count runs.** See `settle_looks`:
    /// a keystroke already in flight when the question arrived is not an answer
    /// to it.
    fn onApprovalKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        if (self.approval == null) return false;

        const typed = event.text orelse return false;
        // `d` and `w` only change what is shown, so they are answered while the
        // region is settling. `y` and `n` decide, so they are not.
        if (std.mem.eql(u8, typed, "d")) {
            self.approval.?.view = if (self.approval.?.view == .diff) .question else .diff;
            return true;
        }
        if (std.mem.eql(u8, typed, "w")) {
            self.approval.?.view = if (self.approval.?.view == .why) .question else .why;
            return true;
        }
        if (self.approval_settle != 0) return false;
        if (std.mem.eql(u8, typed, "y")) {
            self.approval_answer = .approved;
            return true;
        }
        if (std.mem.eql(u8, typed, "n")) {
            self.approval_answer = .refused;
            return true;
        }
        return false;
    }

    fn onApprovalFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.approval_focused = focused;
    }

    /// The line editor of the question region.
    ///
    /// **It produces words and nothing else.** There is no key here that means
    /// "allowed", and no field on this display it could write one into: see
    /// `Question` and `Text`. The region above this one answers `y` and `n`, and
    /// a reader who wants to add either here should read
    /// `lib/chock-core/ask.zig`'s own top comment first.
    ///
    /// **A digit chooses from the list only while the answer line is empty**, so
    /// a person writing "1 or 2, whichever is cheaper" types a sentence and not
    /// an answer to the first character of it. The number is the option's own
    /// text by the time it leaves here, which is what `chock_core.ask.chosen`
    /// does with a typed number at the bare prompt.
    fn onQuestionKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        const one = self.question orelse return false;

        switch (event.keysym) {
            // **Enter with nothing typed is a deliberate "no answer"**, which is
            // a different fact from nobody being there, and the model is told
            // which of the two it got: see `chock_core.ask.Answer`.
            .enter => {
                if (self.question_settle != 0) return false;
                self.question_said = if (self.question_filled == 0) .declined else .answered;
                return true;
            },
            .backspace => {
                self.question_filled = backOne(self.question_typed[0..self.question_filled]);
                return true;
            },
            else => {},
        }

        const typed = event.text orelse return false;
        if (typed.len == 0) return false;

        if (self.question_filled == 0 and one.options.len != 0 and typed.len == 1) {
            if (typed[0] >= '1' and typed[0] <= '9') {
                if (self.question_settle != 0) return false;
                const index: usize = typed[0] - '1';
                if (index < one.options.len) {
                    const chose = one.options[index];
                    if (chose.len <= self.question_typed.len) {
                        @memcpy(self.question_typed[0..chose.len], chose);
                        self.question_filled = chose.len;
                        self.question_said = .answered;
                        return true;
                    }
                }
            }
        }

        // A control byte is not a character of an answer. Every one of them
        // either has a meaning above or has none here at all, and letting one
        // into the buffer would put it in the tool result and in the context.
        for (typed) |byte| {
            if (byte < 0x20 or byte == 0x7f) return false;
        }
        if (self.question_filled + typed.len > self.question_typed.len) return false;
        @memcpy(self.question_typed[self.question_filled..][0..typed.len], typed);
        self.question_filled += typed.len;
        return true;
    }

    fn onQuestionFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.question_focused = focused;
    }

    /// The keys that belong to the session rather than to a region.
    ///
    /// **Last in the dispatch order**, so a region that wanted the key has
    /// already had it: phantom offers the focused node first, then the
    /// traversal rules, then these. `↑` and `↓` are here because they belong to
    /// the session and the message field declines them, so they scroll the
    /// transcript whichever region a person is in.
    fn onSessionKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));

        // **The list that is open takes the arrows.** Both lists belong to the
        // input region, so a person choosing in one is moving through their own
        // list rather than scrolling a neighbour. The transcript's own handler
        // runs before this one, so a person who has moved the focus there
        // scrolls instead: see `onTranscriptKey`.
        var slots: [Command.all.len]Command = undefined;
        const listed = self.openCompletions(&slots);
        const offered = self.picker orelse &[_]Resumable{};

        switch (event.keysym) {
            .up => {
                if (offered.len != 0) {
                    self.picked -|= 1;
                } else if (listed.len != 0) {
                    self.completion_selected -|= 1;
                } else self.scrollBy(1);
                return true;
            },
            .down => {
                if (offered.len != 0) {
                    self.picked = @min(self.picked + 1, offered.len - 1);
                } else if (listed.len != 0) {
                    self.completion_selected = @min(self.completion_selected + 1, listed.len - 1);
                } else self.scrollBy(-1);
                return true;
            },
            // **There is no dismiss key, and that is measured rather than
            // chosen.** `Esc` was the obvious one and phantom already owns it:
            // its focus manager answers Escape in the traversal rules, before
            // any listener is offered the key, by clearing the focus. `Esc` has
            // two other meanings and none of them is this. So the list is
            // dismissed by typing: one more character that is not a command's,
            // or a backspace over the slash, and it closes. See `completions`.
            else => return false,
        }
    }

    /// One row of the transcript, in the voice it was said in.
    ///
    /// **Chock's rail and the agent's indent are put here**, in front of text
    /// the agent supplied, and the agent has no way to write before them. That
    /// is the structural half of the voice rule: see `Voice`.
    ///
    /// **Wrapped, and never cut.** `showRows` has already broken a long line
    /// into rows that fit, and every one of those rows is in the same voice, so
    /// a continuation of an agent line still carries the agent's indent and
    /// still cannot reach column 0. That is the same guarantee the cut used to
    /// give, kept while the words survive: the agent only ever supplies the
    /// text inside its own block.
    ///
    /// **The indent is a container and no longer a string.** The agent's rows
    /// are drawn inside a `Padding`, so the two columns in front of them are
    /// layout rather than two spaces pasted on to the agent's own bytes. There
    /// is nothing an agent can write that puts its text before them.
    ///
    /// **The marker is placed by layout and not by counting spaces.** See
    /// `pinnedRow`.
    fn voicedRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        line: Shown,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        // **The blank row between two blocks carries no voice at all.** Not a
        // rail, not an indent, and nothing an agent could have said. See
        // `Line.gap`.
        if (line.gap) return plainRow(ctx, "", colors.fg);

        // **The marker is Chock's and sits at the right hand end**, past the
        // agent's own words and never before them. See `markerText`.
        const focused = line.fold_at != null and
            self.transcript_focused and
            self.cursor != null and
            self.cursor.? == line.fold_at.?;
        const marker = if (line.fold_at == null) "" else markerText(line.open, focused);
        // **One right hand column, and the marker has first claim on it.** A
        // row that folds offers a key and that key has to be readable; a clock
        // and a duration are values the eye can ignore, which is what the
        // column is for. No row Chock builds asks for both.
        const right = if (marker.len != 0) marker else line.pinned;
        // The words this row has left once the value has its columns, and a
        // value too wide for the row takes the whole of it. `spread` decides
        // both, so a row that is drawn and a row that is only measured cannot
        // answer differently.
        //
        // **Laid out here and not where the row was built**, so the row is
        // measured against the room it has now. A row padded out at build time
        // wrapped its value away the moment the window narrowed, and never got
        // it back. See `Line.pinned`.
        const words = spread(ctx.arena, line.text, right, self.roomFor(line.voice)) catch "";
        const cut = std.mem.trimEnd(u8, words, " ");
        const pinned = right.len != 0 and std.mem.endsWith(u8, cut, right);
        const left = if (!pinned)
            cut
        else
            std.mem.trimEnd(u8, cut[0 .. cut.len - right.len], " ");

        // **Focus does not change the colour of a row, and that is
        // deliberate.** The accent has two meanings, Chock's rail and focus,
        // and an agent row painted in the rail's colour would spend one of the
        // three signals that say who is speaking. The marker names the key
        // instead, which is a signal colour cannot lose.
        const tone = switch (line.voice) {
            // The third signal, and never the only one.
            .chock => colors.blue_light,
            .agent => colors.fg,
        };
        const said = self.voicedText(ctx, measure, line.voice, left, tone);
        if (!pinned) return said;
        // **Pinned inside the measure the row was cut to, and not inside the
        // band.** The band is the whole display and the transcript stops at a
        // readable measure, so a marker aligned to the band would sit far to
        // the right of the words it belongs to on a wide screen. See `spread`,
        // which measures the same row: the two must answer alike.
        return pinnedRow(
            ctx,
            measure,
            self.transcriptRoom().width,
            said,
            row(ctx, measure, right, tone),
        );
    }

    /// The words of one row, with the leading structure its voice gives it.
    ///
    /// **Chock's rail is a glyph and the agent's indent is a box.** The rail is
    /// Chock's own content and belongs in Chock's own run of text. The indent
    /// is not content at all: it is where the agent's block begins, so it is a
    /// `Padding` around the agent's run and nothing the agent writes can be put
    /// before it. The design draws the same split, a border for one and a
    /// margin for the other.
    fn voicedText(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        voice: Voice,
        words: []const u8,
        tone: phantom.Color,
    ) phantom.Widget {
        _ = self;
        return switch (voice) {
            .chock => row(ctx, measure, std.fmt.allocPrint(ctx.arena, "{s}{s}", .{
                Voice.chock.prefix(),
                words,
            }) catch Voice.chock.prefix(), tone),
            .agent => ctx.new(phantom.Padding{
                .insets = .{
                    // The indent is exactly as wide as the words it stands for,
                    // measured in the face the row is drawn in, so it lines up
                    // with the rail on the rows beside it.
                    .left = measure.widthOf(Voice.agent.prefix()),
                },
                .child = row(ctx, measure, words, tone),
            }).widget(),
        };
    }

    /// A row with `left` at its start and `right` against its end.
    ///
    /// **This is the label and the right pinned value, laid out.** Counting the
    /// spaces between them works on a character grid and nowhere else: a real
    /// font has no column, so a count of spaces is a count of a width that
    /// varies with the letters in it, and the value walks. Two `Align`s inside
    /// a `Stack` put the value against the right edge of whatever the row
    /// really measures, which lands on the same cell on a grid and on the true
    /// edge in pixels.
    ///
    /// **The box is one measured line box tall.** `Align` fills every axis it
    /// is given a bound on, and a transcript row is inside a `Column` that
    /// offers the whole band, so without a height every row would be the whole
    /// band and only the first would be seen.
    ///
    /// **The left is drawn first and therefore sizes the stack.** It fills the
    /// width, so the right is pinned inside the whole row and not inside the
    /// words.
    ///
    /// **The box is `across` wide, which is the measure the row was cut to and
    /// not the band.** The transcript stops growing at a readable measure, so a
    /// row aligned to the band would put its marker at the far edge of a wide
    /// display, tens of columns from the words it belongs to.
    fn pinnedRow(
        ctx: *phantom.BuildContext,
        measure: Measure,
        across: f32,
        left: phantom.Widget,
        right: phantom.Widget,
    ) phantom.Widget {
        const both = ctx.newSlice(phantom.Widget, &.{
            ctx.new(phantom.Align{ .alignment = .top_left, .child = left }).widget(),
            ctx.new(phantom.Align{ .alignment = .top_right, .child = right }).widget(),
        });
        return ctx.new(phantom.SizedBox{
            .width = across,
            .height = measure.height(),
            .child = ctx.new(phantom.Stack{ .children = both }).widget(),
        }).widget();
    }

    /// One run of text.
    ///
    /// **No size is named here, and that is the whole of the fix.** A size this
    /// file chose would be a size it invented: the character grid ignores one
    /// outright, and the pixel backend would draw the font at whatever number
    /// was written down, which is how a nominal cell height became a font size.
    /// Leaving it out gives the run the theme's size, which is the one place a
    /// size belongs, and `Measure` reads the same theme so a band and the text
    /// on it can never disagree.
    ///
    /// **The role and the level only.** A component names a role and a level,
    /// never a font, a pixel size, or a colour. The colour here is a role from
    /// the scheme and there is nothing else. **A mark is lifted out of the run
    /// and drawn by phantom.** See `marked`, which is where that happens and
    /// why almost every row skips it.
    fn row(
        ctx: *phantom.BuildContext,
        measure: Measure,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        if (marked(ctx, measure, text, color)) |made| return made;
        return plainRow(ctx, text, color);
    }

    fn plainRow(
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return ctx.new(phantom.Text{
            .text = text,
            .color = color,
        }).widget();
    }

    /// `text` as runs of words with a drawn mark in place of each codepoint
    /// `markFor` knows, or null when it holds none.
    ///
    /// **Null is the answer for almost every row**, and that is what keeps one
    /// run of text one run. A `phantom.Row` around a single `phantom.Text`
    /// measures and lays the same bytes out through two more boxes for nothing.
    ///
    /// **The box is the run's own width and one line box tall.** A horizontal
    /// `phantom.Flex` with a bounded main axis reports the whole box it was
    /// offered, not what its children take, so without this the first header
    /// piece that held a mark claimed the whole header and every piece after it
    /// was pushed off the screen. `Measure.widthOf` is the same sum the
    /// children measure themselves by, one glyph at a time.
    ///
    /// **A row that cannot be built is drawn as its own text.** The characters
    /// are the ones a cell backend would have painted anyway, so the fallback
    /// loses the vectors and none of the words.
    fn marked(
        ctx: *phantom.BuildContext,
        measure: Measure,
        text: []const u8,
        color: phantom.Color,
    ) ?phantom.Widget {
        var pieces: std.ArrayList(phantom.Widget) = .empty;
        var index: usize = 0;
        var kept: usize = 0;
        while (index < text.len) {
            const one = drawnAt(text, index);
            const mark = if (one.whole) markFor(one.point) else null;
            // **A face that advances nowhere for this codepoint keeps the
            // character.** The mark is drawn inside the room the codepoint was
            // measured to take, and a box of no width paints nothing at all.
            const width = if (mark == null) 0 else measure.advanceOf(one.point);
            if (mark == null or !(width > 0)) {
                index += one.length;
                continue;
            }
            if (index > kept) pieces.append(ctx.arena, plainRow(
                ctx,
                text[kept..index],
                color,
            )) catch return null;
            pieces.append(
                ctx.arena,
                markBox(ctx, measure, mark.?, width, color),
            ) catch return null;
            index += one.length;
            kept = index;
        }
        if (pieces.items.len == 0) return null;
        if (kept < text.len) pieces.append(ctx.arena, plainRow(
            ctx,
            text[kept..],
            color,
        )) catch return null;
        return ctx.new(phantom.SizedBox{
            .width = measure.widthOf(text),
            .height = measure.height(),
            .child = ctx.new(phantom.Row(.{ .children = pieces.items })).widget(),
        }).widget();
    }

    /// One mark, in the room the codepoint it stands for was measured to take.
    ///
    /// **`across` is that codepoint's own advance**, so nothing that measured
    /// the text can disagree with what is drawn: `wrapText`, `visibleLine` and
    /// `spread` all step by `Measure.advanceOf` and this asks for the same
    /// number. On a character grid that is exactly one cell, which is what
    /// leaves a terminal capture unchanged.
    ///
    /// **A rule takes the whole row and a symbol stays square.** A row is
    /// taller than a cell is wide, so a rule kept square leaves the rest of the
    /// row blank and a stack of rows draws the rail dashed. A tick has shape in
    /// both axes and comes out distorted if it is stretched, so it keeps the
    /// shorter side and is centred down the row.
    ///
    /// **Two things say the rule apart, and both are needed.** `.fit = .fill`
    /// is what makes `phantom.Icon` paint into the box it was given rather than
    /// the square inside it, and giving the icon to the `SizedBox` directly is
    /// what makes that box the whole row: `phantom.Align` hands its child loose
    /// constraints, so an icon under one measures itself square whatever `fit`
    /// says.
    fn markBox(
        ctx: *phantom.BuildContext,
        measure: Measure,
        mark: Mark,
        across: f32,
        color: phantom.Color,
    ) phantom.Widget {
        const icon = ctx.new(phantom.Icon{
            .id = mark.id,
            .size = across,
            .fit = if (isRule(mark.id)) .fill else .square,
            .color = color,
            .label = mark.label,
        }).widget();
        return ctx.new(phantom.SizedBox{
            .width = across,
            .height = measure.height(),
            .child = if (isRule(mark.id)) icon else ctx.new(phantom.Align{
                .alignment = .center,
                .child = icon,
            }).widget(),
        }).widget();
    }

    /// True for a mark that means a line rather than a symbol.
    ///
    /// **Read from phantom rather than listed again here.** `cellMarkFor` marks
    /// exactly the pair that continues past its own box, which is the same
    /// question the pixel backend asks, so a mark phantom adds later is
    /// answered here without a second list to keep in step.
    fn isRule(id: phantom.icon.Id) bool {
        const cell = phantom.icon.cellMarkFor(id) orelse return false;
        return cell.tile;
    }

    fn rootOf(ctx: *phantom.BuildContext, self: *Ui) phantom.Widget {
        return phantom.StatefulWidget(Screen, ctx.new(Screen{ .ui = self }));
    }
};

/// The one stateful widget in the tree, and the only reason it is stateful:
/// phantom mounts a root once and rebuilds only what has been marked dirty, so
/// without a state to mark there would be one frame and no more.
const Screen = struct {
    ui: *Ui,

    pub const State = struct {
        base: phantom.StateBase = .{},
        ui: ?*Ui = null,

        pub fn initState(self: *State, config: *const Screen) !void {
            self.ui = config.ui;
            // How `Ui.draw` reaches back to ask for a frame.
            config.ui.screen = self;
        }

        pub fn build(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const ui = self.ui orelse return ctx.new(phantom.Text{ .text = "" }).widget();
            return ui.view(ctx);
        }
    };
};

const testing = std.testing;

test "a window phantom offers is drawn, and the terminal has no say in it" {
    // A `.gpu` answer is a window that can really be opened: there is a screen
    // and a frame can be drawn on it. See `windowPossible`. Nothing about the
    // terminal may take it away: a person with a compositor who runs `chock`
    // from a terminal wants the window.
    //
    // Mutation check: make the `.gpu` arm read `terminal_can_draw` and the
    // second line fails, which is `chock` in a Wayland session drawing in the
    // terminal it was typed in.
    try testing.expectEqual(Plan.window, decide(.gpu, true));
    try testing.expectEqual(Plan.window, decide(.gpu, false));
}

test "a desktop is named from the environment alone, and an empty value is not one" {
    // The regression this exists for. Asking the drawing half first made a
    // machine with a screen decline the window in silence, because the branch
    // that used to explain itself was in `Ui.start` and is never reached now.
    // This is what decides whether anybody hears about it.
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    // Nothing set. A session over ssh, which must stay quiet.
    try testing.expect(!namesADisplay(&env));

    // **Set and empty is not a desktop.** A shell that exports an unset variable
    // would otherwise make every headless run print a line about a window,
    // which is the same rule `tty.decide` keeps for `NO_COLOR`.
    try env.put("WAYLAND_DISPLAY", "");
    try testing.expect(!namesADisplay(&env));

    try env.put("WAYLAND_DISPLAY", "wayland-0");
    try testing.expect(namesADisplay(&env));

    // Either one alone is enough: an X session names only the second.
    var x_only: std.process.Environ.Map = .init(testing.allocator);
    defer x_only.deinit();
    try x_only.put("DISPLAY", ":0");
    try testing.expect(namesADisplay(&x_only));

    // Mutation check: drop the `value.len != 0` guard and the empty case above
    // reads true, which is a line printed on every headless run.
}

test "a device that cannot draw ends it, and the compositor is never asked" {
    // An Apple M1 running cosmic-comp is the machine this is here for: there
    // was a screen and there was a device, `phantom.window.available` said yes,
    // and the session then failed with `NotImplemented`.
    var asked: u32 = 0;
    const Fake = struct {
        asked: *u32,
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            self.asked.* += 1;
            return self.answer;
        }
    };

    // Mutation check: drop the early return from `windowPossible` and the count
    // below reads 1, which is bare `chock` spending a compositor connection on
    // a window it has already ruled out.
    try testing.expectEqual(Compositor.Answer.none, windowPossible(false, Fake{ .asked = &asked, .answer = .ready }));
    try testing.expectEqual(@as(u32, 0), asked);

    // The rest of the table, so this is a rule and not a refusal. Mutation
    // check: return `.none` from `windowPossible` whatever it was told and the
    // last line fails, which is a machine that can draw losing its window.
    try testing.expectEqual(Compositor.Answer.none, windowPossible(true, Fake{ .asked = &asked, .answer = .none }));
    try testing.expectEqual(@as(u32, 1), asked);
    try testing.expectEqual(Compositor.Answer.ready, windowPossible(true, Fake{ .asked = &asked, .answer = .ready }));
    try testing.expectEqual(@as(u32, 2), asked);
}

test "a keyboard that spells nothing loses the window, and the terminal keeps it" {
    // The second half of the same rule, and the fault it was written for: the
    // window came up on a seated compositor, it drew every frame, and not one
    // key reached it. A person watching that has a product that looks like it
    // works and does nothing at all.
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("WAYLAND_DISPLAY", "wayland-0");

    const Fake = struct {
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            return self.answer;
        }
    };

    // A screen that draws and a keymap that did not read. Mutation check: let
    // `start` pass `window != .none` to `selectBackend` instead of
    // `window == .ready` and this reads `.window`, which is the fault in full.
    const mute = windowPossible(true, Fake{ .answer = .no_keys });
    try testing.expectEqual(Compositor.Answer.no_keys, mute);
    try testing.expectEqual(
        Plan.terminal,
        decide(phantom.app.selectBackend(&env, mute == .ready, true), true),
    );

    // **The terminal display is what it drops to, and the usage page is not.**
    // A keyboard the window could not read says nothing about the terminal the
    // person typed `chock` in, which reads its own keys and always has.
    try testing.expectEqual(
        Plan.usage,
        decide(phantom.app.selectBackend(&env, mute == .ready, false), false),
    );

    // And the same machine with a keymap that reads keeps its window, so this
    // is about the keyboard and not about the compositor.
    const ready = windowPossible(true, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.window,
        decide(phantom.app.selectBackend(&env, ready == .ready, true), true),
    );
}

test "the one line lattice writes about a keymap is the one this listens for" {
    // The channel and the match, without a compositor. `saysKeymapFailed` is
    // read at comptime by `logMessage`, so this is the whole of what decides
    // whether a keyboard is in doubt.
    try testing.expect(saysKeymapFailed(
        .warn,
        "lattice: compositor keymap did not parse, keeping the previous one",
    ));

    // **Wide on the words and narrow on the level.** A keymap that is merely
    // reported is not a keymap that failed: lattice says what it bound at
    // `info` on every window run, and a window must not drop to cells for it.
    //
    // Mutation check: drop the level guard and the second line reads true,
    // which is every desktop losing its window to a message about nothing.
    try testing.expect(saysKeymapFailed(.err, "keymap"));
    try testing.expect(!saysKeymapFailed(.info, "lattice: keymap loaded"));
    try testing.expect(!saysKeymapFailed(.warn, "lattice: no pointer on this seat"));
}

test "a screen with no way to draw on it leaves the terminal display standing" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    // A Wayland session whose device cannot draw a frame. The window is out,
    // and what is left is the terminal the person typed in. **Not the usage
    // page**: a display that cannot start is answered by the display that can,
    // and only a stream that is no terminal at all takes that away.
    try env.put("WAYLAND_DISPLAY", "wayland-0");

    const Fake = struct {
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            return self.answer;
        }
    };

    // Mutation check: let `windowPossible` ignore `can_draw` and this reads
    // `.window`, which is the fault: a window is opened, it fails, and the
    // terminal display that would have worked is never reached.
    const no_frame = windowPossible(false, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.terminal,
        decide(phantom.app.selectBackend(&env, no_frame == .ready, true), true),
    );
    try testing.expectEqual(
        Plan.usage,
        decide(phantom.app.selectBackend(&env, no_frame == .ready, false), false),
    );

    // The same session on a device that does draw is the window, so the two
    // lines above are about the device and not about `WAYLAND_DISPLAY`.
    const frame = windowPossible(true, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.window,
        decide(phantom.app.selectBackend(&env, frame == .ready, true), true),
    );
}

test "nothing to draw on is the usage page, which is what bare chock always printed" {
    // `chock | head` and `chock > notes` in a script. Neither wants a full
    // screen application, and both already get the usage page today.
    //
    // Mutation check: make `.none` draw the terminal display and a piped bare
    // `chock` fills the pipe with cursor moves.
    try testing.expectEqual(Plan.usage, decide(.none, false));
    // Phantom answers `.none` for a stream that is not a terminal whatever else
    // is true, so this is the same case with the other input flipped.
    try testing.expectEqual(Plan.usage, decide(.none, true));

    // A terminal phantom accepted that cannot show an escape sequence. Phantom
    // reads the descriptor and never `TERM`, so this half is Chock's to answer.
    // Mutation check: drop `terminal_can_draw` from the `.tui` arm and
    // `TERM=dumb` gets a full screen application.
    try testing.expectEqual(Plan.usage, decide(.tui, false));

    // The other half, so the two above are about the rule and not about a
    // decision that only ever says no.
    try testing.expectEqual(Plan.terminal, decide(.tui, true));
}

test "a terminal that says dumb, or says nothing, cannot be drawn on" {
    // The rule lives in `src/tty.zig` and this is the reader that needs it for
    // a display rather than for a colour. Mutation check: let a null `TERM`
    // through and a session over a serial line with no `TERM` takes the
    // alternate screen.
    try testing.expect(!tty.terminalCanDraw(null));
    try testing.expect(!tty.terminalCanDraw(""));
    try testing.expect(!tty.terminalCanDraw("dumb"));
    try testing.expect(tty.terminalCanDraw("xterm-256color"));
    try testing.expect(tty.terminalCanDraw("screen"));
}

test "no colour still means a display, drawn with no SGR byte in it" {
    // **`NO_COLOR` says no colour, not no interface.** Before this the two were
    // one answer and setting it would have taken the whole display away.
    //
    // Mutation check: drop the `.color` line in `Ui.options` and a frame drawn
    // under `NO_COLOR` carries SGR sequences.
    const gpa = testing.allocator;
    defer tty.configure(.{});

    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color", .no_color = "1" });
    try testing.expect(!tty.stdoutPainter().on);

    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.observer().onPiece(.{ .text = "a line with no colour\n" });

    // The words are there, so the display really drew.
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "a line with no colour") != null);
    // And not one SGR sequence anywhere. Every escape phantom writes here is a
    // cursor move or a screen mode, and `\x1b[` followed by an `m` is the one
    // shape a colour takes.
    try testing.expect(!holdsSgr(h.sink.bytes.items));

    // The other half: with the painter on, the frame does carry colour, so the
    // line above is about the option and not about a display that never paints.
    h.stop();
    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color" });
    try testing.expect(tty.stdoutPainter().on);

    const painted = try Headless.open(gpa);
    defer painted.close();
    painted.screen.observer().onPiece(.{ .text = "a line with colour\n" });
    try testing.expect(holdsSgr(painted.sink.bytes.items));
}

/// True when `bytes` holds an SGR sequence, which is `\x1b[`, digits and
/// semicolons, then `m`. Written here rather than looked for as a fixed string,
/// because a colour's parameters depend on what the terminal said it takes.
fn holdsSgr(bytes: []const u8) bool {
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, bytes, at, "\x1b[")) |found| {
        var index = found + 2;
        while (index < bytes.len and (std.ascii.isDigit(bytes[index]) or bytes[index] == ';')) {
            index += 1;
        }
        if (index < bytes.len and bytes[index] == 'm') return true;
        at = found + 2;
    }
    return false;
}

test "a window waits for nothing during a turn, and for a tenth of a second at the field" {
    // **The fault this is about.** A look is bounded by the keyboard device:
    // `enterRaw` sets `VMIN 0` and `VTIME 1`, so the read at the end of one
    // comes back within a tenth of a second. A window has no such device, so
    // the loop waiting for the first message drew a frame and asked for the
    // next with no wait at all. Measured on weston: 99 percent of one core,
    // and 13,717 turns of the loop for every frame that reached the screen.
    //
    // **The two numbers are different on purpose.** Zero is right while a turn
    // runs, because a display must not pace a session; a tenth of a second is
    // right while the session is waiting for a person, because nothing is
    // being paced then. See `windowOptions` and `Ui.look_ms`.
    //
    // Mutation check: put `Ui.look_ms` back to zero and the field spins again.
    try testing.expectEqual(@as(?u32, 0), Ui.windowOptions(.{}).poll_ms);
    try testing.expectEqual(@as(u32, @intCast(chock_core.idle.slice_ms)), Ui.look_ms);
}

test "a look waits for the shorter of its budget and one look" {
    // A budget shorter than a look is a deadline that is nearly up, and a look
    // that waited the whole tenth of a second would expire an approval after
    // the moment it said it would expire. See `Ui.lookWait`.
    try testing.expectEqual(@as(u32, 0), Ui.lookWait(0));
    try testing.expectEqual(@as(u32, 7), Ui.lookWait(7));
    try testing.expectEqual(Ui.look_ms, Ui.lookWait(Ui.look_ms));
    try testing.expectEqual(Ui.look_ms, Ui.lookWait(60_000));
}

test "a terminal look draws exactly as it did, whatever wait it is given" {
    // **The terminal path must be untouched by the window's fix.** Its own
    // device is the bound and it is the shorter of the two, so a wait here
    // would only be a second one after it: `Surface.stepWaiting` drops it.
    const gpa = testing.allocator;
    defer tty.configure(.{});
    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color" });

    const h = try Headless.open(gpa);
    defer h.close();

    // A row that is on the display and has not been drawn yet, so the frame
    // below is the one that puts it there. `say` builds the row and draws
    // nothing; every other path draws for itself and would leave nothing to
    // see. See `draw`.
    h.screen.say(.chock, "a line drawn while waiting");
    h.screen.endLine();

    const before = h.sink.bytes.items.len;
    try testing.expect(h.screen.paintWaiting(Ui.look_ms));
    // A frame really went out, so the wait took nothing away from the draw.
    try testing.expect(h.sink.bytes.items.len > before);
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "a line drawn while waiting") != null);
}

test "the header and the input each keep a row, and the transcript gets the rest" {
    // The ordinary screen. Mutation check: give the transcript the whole height
    // and the two bands vanish, which is the screen the owner said does not look
    // like the prototype.
    const parts = split(24, 0);
    try testing.expectEqual(@as(u16, 1), parts.header);
    try testing.expectEqual(@as(u16, 22), parts.transcript);
    try testing.expectEqual(@as(u16, 0), parts.approval);
    try testing.expectEqual(@as(u16, 1), parts.input);
    try testing.expectEqual(@as(u16, 24), parts.header + parts.transcript + parts.approval + parts.input);
}

test "an approval takes its rows from the transcript and from neither band" {
    // On a very short screen the header and the approval keep their rows. The
    // transcript gives up rows first, because it is the one thing that can be
    // scrolled back to.
    //
    // Mutation check: take the approval's rows off the input band and a person
    // with a question in front of them loses the line they type into; take them
    // off the header and they lose the sandbox layers while being asked to let
    // something out of the sandbox.
    const parts = split(24, 6);
    try testing.expectEqual(@as(u16, 1), parts.header);
    try testing.expectEqual(@as(u16, 16), parts.transcript);
    try testing.expectEqual(@as(u16, 6), parts.approval);
    try testing.expectEqual(@as(u16, 1), parts.input);

    // A screen with no room left gives the transcript up altogether and the
    // question is still whole.
    const tight = split(8, 6);
    try testing.expectEqual(@as(u16, 0), tight.transcript);
    try testing.expectEqual(@as(u16, 6), tight.approval);
    try testing.expectEqual(@as(u16, 1), tight.header);
    try testing.expectEqual(@as(u16, 1), tight.input);

    // And a question larger than the screen takes what there is rather than
    // pushing a band off the bottom.
    const smaller = split(5, 6);
    try testing.expectEqual(@as(u16, 3), smaller.approval);
    try testing.expectEqual(@as(u16, 5), smaller.header + smaller.transcript +
        smaller.approval + smaller.input);
}

test "a very short screen gives its rows up from the transcript first" {
    // The header and the approval keep their rows and the transcript gives up
    // rows first, because the transcript is the one thing that can be scrolled
    // back to.
    //
    // Mutation check: take the rows off the bands rather than the transcript
    // and a short screen loses the line a person types into.
    const two = split(2, 0);
    try testing.expectEqual(@as(u16, 1), two.header);
    try testing.expectEqual(@as(u16, 0), two.transcript);
    try testing.expectEqual(@as(u16, 1), two.input);

    // One row is the input alone: a person who cannot type cannot leave.
    const one = split(1, 0);
    try testing.expectEqual(@as(u16, 1), one.input);
    try testing.expectEqual(@as(u16, 0), one.header);
    try testing.expectEqual(@as(u16, 0), one.transcript);

    // And nothing at all is nothing at all.
    const none = split(0, 0);
    try testing.expectEqual(@as(u16, 0), none.header + none.transcript + none.input);
}

test "one row of the transcript is written per newline, whoever said it" {
    // The rows are built from what the observer delivered, not from parsing
    // the transcript's bytes back apart, so a change of voice closes the row
    // that was open. Mutation check: drop the `endLine` in `say` when the voice
    // changes and the agent's words land under Chock's rail.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.agent, "one\ntwo\n");
    h.screen.say(.chock, "three\n");
    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[0].voice);
    try testing.expectEqualStrings("one", h.screen.lines.items[0].text);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
    try testing.expectEqualStrings("two", h.screen.lines.items[1].text);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[2].voice);
    try testing.expectEqualStrings("three", h.screen.lines.items[2].text);

    // A row with no newline yet is held, not shown as finished. That is the
    // model's answer arriving a few characters at a time.
    h.screen.say(.agent, "half a ");
    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    h.screen.say(.agent, "line\n");
    try testing.expectEqual(@as(usize, 4), h.screen.lines.items.len);
    try testing.expectEqualStrings("half a line", h.screen.lines.items[3].text);

    // **The case the guard exists for**: the agent stops mid row and Chock
    // speaks. Without closing the open row first, the agent's unfinished words
    // and Chock's own would become one row, tagged Chock, and the agent's text
    // would sit under Chock's rail. That is the attack `Voice` is about.
    h.screen.say(.agent, "the model was saying");
    h.screen.say(.chock, "session ended, finished\n");
    try testing.expectEqual(@as(usize, 6), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[4].voice);
    try testing.expectEqualStrings("the model was saying", h.screen.lines.items[4].text);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[5].voice);
    try testing.expectEqualStrings("session ended, finished", h.screen.lines.items[5].text);
}

test "the rows shown are the newest ones, in the order they were said" {
    // Mutation check: take the last `count` from the front and a session shows
    // its first four rows for ever.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    h.screen.say(.agent, "one\ntwo\nthree\nfour\n");
    const shown = h.screen.visibleRows(arena, 2);
    try testing.expectEqual(@as(usize, 2), shown.len);
    try testing.expectEqualStrings("three", shown[0].text);
    try testing.expectEqualStrings("four", shown[1].text);

    // Fewer rows than the screen has gives every one of them and no blank.
    const all = h.screen.visibleRows(arena, 10);
    try testing.expectEqual(@as(usize, 4), all.len);
    try testing.expectEqualStrings("one", all[0].text);
}

test "an escape sequence in a row never reaches a cell" {
    // The fault this guards: a cell holds a codepoint and the frame writer
    // sends it straight at the terminal, so an escape byte from a tool's own
    // output would become an escape sequence this file never composed.
    //
    // Mutation check: take the control character branch out of `visibleLine`
    // and the escape byte arrives.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shown = try visibleLine(arena, "before\x1b[31mred\x07 after", Room.grid(80));
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x07) == null);
    try testing.expectEqualStrings("before [31mred  after", shown);
}

test "a row is cut by columns, so a wide glyph is not cut in half" {
    // Japanese is two columns to a glyph. A cut by bytes would land inside a
    // sequence and phantom, which decodes a line to measure it, would then drop
    // the whole line.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("あい", try visibleLine(arena, "あいうえお", Room.grid(4)));
    try testing.expect(std.unicode.utf8ValidateSlice(try visibleLine(arena, "あいうえお", Room.grid(4))));

    // And an odd number of columns leaves the glyph that would cross the edge
    // off, rather than drawing half of it.
    try testing.expectEqualStrings("あい", try visibleLine(arena, "あいうえお", Room.grid(5)));
}

test "a byte that is not valid UTF-8 becomes a question mark rather than losing the row" {
    // Phantom gives a line it cannot decode no size at all, so one bad byte in
    // a tool's output would make the whole row disappear.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shown = try visibleLine(arena, "good\xffbad", Room.grid(80));
    try testing.expectEqualStrings("good?bad", shown);
    try testing.expect(std.unicode.utf8ValidateSlice(shown));

    // A sequence cut off by the end of the row is the same case.
    try testing.expect(std.unicode.utf8ValidateSlice(try visibleLine(arena, "end\xe3\x81", Room.grid(80))));
}

/// The theme's own body face, for the measurement tests. Every one of them is
/// about a real font, because the fault was a number written down instead of a
/// measurement.
fn themeFont(gpa: std.mem.Allocator) !phantom.text.Font {
    return phantom.text.Font.load(gpa, phantom.text.builtin.mesmerize_rg_bytes);
}

test "a row of the theme's own font is taller than the nominal cell that used to size it" {
    // **This is the header fault, stated as a number.** `logical_cell_h` is 16,
    // and a band built as one of those held a run drawn at size 16. The face's
    // ascent and descent together measure 1.2 em, so the run wants 19.2 and the
    // band gives it 16: every glyph that reaches the baseline is cut.
    //
    // Mutation check: return `size` from `Measure.height` and the two numbers
    // below become equal, which is the bug.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const nominal = phantom.tui.term.logical_cell_h;
    const measured = (Measure{
        .metrics = .proportional,
        .dpr = 1,
        .font = &font,
        .size = nominal,
    }).height();
    try testing.expect(measured > nominal);
    try testing.expectApproxEqAbs(@as(f32, 19.2), measured, 0.01);
}

test "the character grid measures a row as one reported cell, at any device pixel ratio" {
    // **The check that the measurement is not a new invention.** A cell grid
    // draws one row per cell, so a display of N cell rows must still be N rows
    // of text however many physical pixels a cell covers. The mono metrics are
    // physical and everything a widget is given is logical, so the ratio has to
    // divide back out exactly.
    //
    // Mutation check: drop the divide by `dpr` and the HiDPI terminal below
    // reports less than half the rows it has.
    //
    // An ordinary terminal, cell 9 by 18, and a HiDPI one, cell 19 by 37. Both
    // show 24 rows, and a row of both holds 80 cells and not 81.
    for ([_][2]f32{ .{ 9, 18 }, .{ 19, 37 } }) |cell| {
        const dpr = cell[1] / phantom.tui.term.logical_cell_h;
        const measure = Measure{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(cell[0], cell[1]) },
            .dpr = dpr,
            .font = undefined,
            .size = 0,
        };
        try testing.expectApproxEqAbs(
            phantom.tui.term.logical_cell_h,
            measure.height(),
            0.001,
        );
        // The logical viewport phantom reports for that terminal.
        const logical_h = 24 * cell[1] / dpr;
        const logical_w = 80 * cell[0] / dpr;
        try testing.expectEqual(@as(u16, 24), measure.rowsIn(logical_h));
        // **Measured across and not divided.** A grid is the one case where
        // both answers agree, which is what makes it the check.
        const room = Room{ .measure = measure, .width = logical_w };
        try testing.expect(room.holds("x" ** 80));
        try testing.expect(!room.holds("x" ** 81));
    }
}

/// A proportional measurement of the theme's own face, for the tests below.
fn faceMeasure(font: *phantom.text.Font, size: f32) Measure {
    return .{ .metrics = .proportional, .dpr = 1, .font = font, .size = size };
}

test "a proportional row is measured against its own letters and never divided by a column" {
    // **This is the wrapping fault, stated as two numbers.** A proportional
    // face has no column, and the answer used to be a column as wide as the
    // widest printable glyph. That glyph is far wider than the letters prose is
    // made of, so a viewport divided by it gave about half the characters the
    // row really holds: prose wrapped near the middle of the window, layer
    // names vanished out of the header, and tool call text stopped mid word.
    //
    // Mutation check: fit against `widest` in place of `Measure.advanceOf` and
    // the second expectation fails, because the row then keeps only the count a
    // division allowed.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const size: f32 = 16;
    const measure = faceMeasure(&font, size);
    const across: f32 = 640;
    const room = Room{ .measure = measure, .width = across };

    const words = "the quick brown fox jumps over the lazy dog. " ** 8;
    const cut = try visibleLine(arena, words, room);

    // The promise a cut row keeps: it measures inside the room it was given.
    try testing.expect(measure.widthOf(cut) <= across);

    // And it holds far more than a column count allowed. `widest` below is the
    // old answer, worked out the old way.
    var widest: f32 = 0;
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) widest = @max(widest, font.advance(point, size));
    const divided: usize = @intFromFloat(@floor(across / widest));
    try testing.expect(divided > 0);
    try testing.expect(cut.len > divided * 3 / 2);
}

test "a row of the widest letters still fits, because it is measured too" {
    // **The property the old model bought its columns with.** Erring towards
    // fewer columns could not clip, and a measured row must not give that up: a
    // row of nothing but the face's widest glyph still has to measure inside
    // the room it was cut to.
    //
    // Mutation check: step the fit by `Measure.step` instead of by
    // `Measure.advanceOf` and this row runs past the width it was cut to.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const size: f32 = 16;
    const measure = faceMeasure(&font, size);
    const across: f32 = 640;
    const room = Room{ .measure = measure, .width = across };

    var fattest: u21 = ' ';
    var widest: f32 = 0;
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) {
        const one = font.advance(point, size);
        if (one > widest) {
            widest = one;
            fattest = point;
        }
    }

    var wall: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < 400) : (index += 1) try wall.append(arena, @intCast(fattest));

    const cut = try visibleLine(arena, wall.items, room);
    try testing.expect(cut.len != 0);
    try testing.expect(measure.widthOf(cut) <= across);
    // And exactly as many as fit: one more would cross the edge.
    try testing.expect(measure.widthOf(cut) + widest > across);
}

test "the advances a frame works out once are the advances it would have asked for" {
    // **The cache is the only new thing that can lie.** Every answer is worked
    // out through the same path a caller with no cache takes, so the two can
    // differ only if `measured` indexes wrongly, and a display drawn from a
    // shifted table would wrap every row in the wrong place.
    //
    // Mutation check: fill the table from `at + 1` and every printable
    // codepoint below answers with its neighbour's advance.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const plain = faceMeasure(&font, 24);
    const quick = plain.measured();

    try testing.expectEqual(plain.height(), quick.height());
    try testing.expectApproxEqAbs(plain.step(), quick.step(), 0.0001);
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) {
        try testing.expectEqual(plain.advanceOf(point), quick.advanceOf(point));
    }
    // A codepoint outside the table is still asked of the face.
    try testing.expectEqual(
        plain.advanceOf('\u{3042}'),
        quick.advanceOf('\u{3042}'),
    );
}

test "a viewport with no room and a measurement with no size are counted as nothing" {
    // A backend reports the viewport and a font supplies the step, so neither is
    // this file's to trust. A step of zero would be an unbounded row count and
    // not a large one, which is a hang and not a wrong picture.
    //
    // Mutation check: divide without the guards and the first two lines below
    // return a count built from an infinity.
    try testing.expectEqual(@as(u16, 0), countIn(0, 16));
    try testing.expectEqual(@as(u16, 0), countIn(400, 0));
    try testing.expectEqual(@as(u16, 0), countIn(-400, 16));
    try testing.expectEqual(@as(u16, 25), countIn(400, 16));
    // A whole row and no more: 399 pixels hold 24 rows of 16 and not 25.
    try testing.expectEqual(@as(u16, 24), countIn(399, 16));
    try testing.expectEqual(std.math.maxInt(u16), countIn(1e9, 1));
}

/// Six layers as a real Linux session has them, for the header tests.
const every_layer_on = [_]Layer{
    .{ .name = "net", .note = "off", .state = .on },
    .{ .name = "fs", .note = "worktree", .state = .on },
    .{ .name = "pid", .state = .on },
    .{ .name = "ipc", .state = .on },
    .{ .name = "seccomp", .state = .on },
    .{ .name = "landlock", .state = .on },
};

/// Join a header back into one line, so a test reads what a person reads.
fn headerText(arena: std.mem.Allocator, facts: Facts, cols: f32) ![]const u8 {
    var said: std.ArrayList(HeaderPiece) = .empty;
    try headerPieces(arena, facts, Room.grid(cols), &said);
    var line: std.ArrayList(u8) = .empty;
    for (said.items) |one| try line.appendSlice(arena, one.text);
    return line.items;
}

test "a layer that is not on says so in a word as well as in a glyph and a colour" {
    // No fact may rest on colour alone, and a layer that is off is the row it
    // names. There are three signals for it: the glyph changes, the word `OFF`
    // appears spelled out, and the region turns.
    //
    // Mutation check: give `.off` and `.unsupported` an empty word and the two
    // expectations below fail, which is the layer that is quiet about being
    // missing.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("\u{2713} net off", try layerText(
        arena,
        .{ .name = "net", .note = "off", .state = .on },
        false,
    ));
    try testing.expectEqualStrings("\u{2717} landlock OFF", try layerText(
        arena,
        .{ .name = "landlock", .state = .off },
        false,
    ));
    // A layer this build never had is a different fact from one this session
    // gave up, and it gets a different word rather than the same one.
    try testing.expectEqualStrings("\u{2717} landlock NONE", try layerText(
        arena,
        .{ .name = "landlock", .state = .unsupported },
        false,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        Layer.State.off.word(),
        Layer.State.unsupported.word(),
    ));

    // Every state that is not `on` carries a word, so none of them can be told
    // apart by colour alone.
    for ([_]Layer.State{ .off, .unsupported, .unavailable }) |state| {
        try testing.expect(state.word().len != 0);
        try testing.expectEqualStrings("\u{2717}", state.glyph());
    }
    try testing.expectEqualStrings("", Layer.State.on.word());
}

test "under 60 columns a layer that is on sheds its name and one that is not keeps it" {
    // Under 60 columns this is a phone answering an approval, and the header
    // sheds layer names to glyphs. How it does that is open, and colour decides
    // it: a bare glyph would leave the one fact a person is there for resting
    // on a glyph and a colour, so the layer that is not on keeps its name and
    // its word at every width.
    //
    // Mutation check: shed the name for every layer and the second expectation
    // becomes a lone glyph, which is a sandbox with a hole in it and no word
    // saying so.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("\u{2713}", try layerText(
        arena,
        .{ .name = "seccomp", .state = .on },
        true,
    ));
    try testing.expectEqualStrings("\u{2717} landlock OFF", try layerText(
        arena,
        .{ .name = "landlock", .state = .off },
        true,
    ));

    // And the whole header of a narrow screen still names the layer that is
    // missing, whatever else it had to drop.
    var layers = every_layer_on;
    layers[5] = .{ .name = "landlock", .state = .off };
    const said = try headerText(arena, .{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &layers,
    }, 50);
    try testing.expect(std.mem.indexOf(u8, said, "landlock OFF") != null);
    try testing.expectEqual(@as(usize, 5), std.mem.count(u8, said, "\u{2713}"));
}

test "the layers keep their room and a context fact is what the header drops" {
    // The layers rank first: they are the one part of the header a person is
    // there to see, and the rest is context. At 80 columns, which the design
    // calls the design width, both do not fit, so one has to go.
    //
    // Mutation check: build the context first and let the layers take what is
    // left, and the row below ends mid way through the layers, which is a
    // header that says nothing about whether the sandbox is on.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const facts = Facts{
        .project = "a-project-with-a-long-name",
        .workspace = "worktree",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &every_layer_on,
    };

    const said = try headerText(arena, facts, 80);
    try testing.expect(columnsOf(said) <= 80);
    // Every layer is there, whole.
    for (every_layer_on) |one| {
        try testing.expect(std.mem.indexOf(u8, said, one.name) != null);
    }
    // And a context fact was dropped whole rather than cut in half, so no half
    // a model name reads as a different model.
    try testing.expect(std.mem.indexOf(u8, said, "a-project-with-a-lo") == null);
    // Dropped from the right, and everything after it too: a header with the
    // provider on it and no model would read as the model.
    try testing.expect(std.mem.indexOf(u8, said, "local") == null);

    // With room for everything, nothing is dropped.
    const wide = try headerText(arena, facts, 160);
    try testing.expect(std.mem.indexOf(u8, wide, "a-project-with-a-long-name") != null);
    try testing.expect(std.mem.indexOf(u8, wide, "glm4.7-flash") != null);
    try testing.expect(std.mem.indexOf(u8, wide, "local") != null);
}

test "a header with no layers draws none rather than six that claim nothing" {
    // A display that was never told is a display that must not say the sandbox
    // is on. `Facts.layers` is empty until `src/run.zig` hands the layers over.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const said = try headerText(arena, .{ .project = "chock" }, 80);
    try testing.expectEqualStrings(" chock  chock", said);
    try testing.expect(std.mem.indexOf(u8, said, "\u{2713}") == null);
}

test "a layer that is on is drawn in one colour and a layer that is not in another" {
    // The third signal, and never the only one: a layer that is on gets `ok`
    // and one that is off gets `danger`. Read out of the grid's own cells, so
    // what is pinned is the colour a person sees.
    //
    // Mutation check: draw every layer in one tone and the two expectations
    // below collapse into one colour.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var layers = every_layer_on;
    layers[5] = .{ .name = "landlock", .state = .off };
    h.screen.describe(.{ .layers = &layers });
    _ = h.screen.paint();

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    const first = std.mem.sliceTo(plain.items, '\n');
    try testing.expect(std.mem.indexOf(u8, first, "landlock OFF") != null);

    const colors = phantom.ColorScheme.tokyoNight();
    const on = phantom.backend.cell_grid.Rgb.fromColor(colors.green);
    const off = phantom.backend.cell_grid.Rgb.fromColor(colors.red);
    try testing.expect(!std.meta.eql(on, off));

    // The column each glyph is at, worked out from the row itself rather than
    // counted here, so the test does not have to agree with the layout twice.
    // Bytes are not columns: every glyph above is three bytes and one column.
    const grid = &h.screen.surface.terminal.grid;
    const off_at = columnsOf(first[0..std.mem.indexOf(u8, first, "\u{2717}").?]);
    try testing.expectEqual(off, grid.cellAt(@intFromFloat(off_at), 0).?.fg);
    const on_at = columnsOf(first[0..std.mem.indexOf(u8, first, "\u{2713}").?]);
    try testing.expectEqual(on, grid.cellAt(@intFromFloat(on_at), 0).?.fg);
}

/// One buffer standing in for the terminal every frame reaches. The same shape
/// `src/tty.zig`'s own tests use, and for the same reason: what is under test is
/// an order across one place, and two buffers cannot hold an order between them.
const Sink = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *Sink) void {
        self.bytes.deinit(self.gpa);
    }

    fn tap(self: *Sink) Tap {
        return self.tapWith(&.{});
    }

    /// The same tap, holding bytes back until it is flushed. **What `main`
    /// really gives standard output**, and the only shape that can tell a
    /// writer which flushes from one which does not: see the test on `Frames`.
    fn tapWith(self: *Sink, buffer: []u8) Tap {
        return .{ .writer = .{ .vtable = &Tap.vtable, .buffer = buffer }, .sink = self };
    }

    const Tap = struct {
        writer: std.Io.Writer,
        sink: *Sink,

        const vtable: std.Io.Writer.VTable = .{ .drain = drain };

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Tap = @fieldParentPtr("writer", w);
            const gpa = self.sink.gpa;
            // The contract in `std.Io.Writer.VTable.drain`: what is already
            // buffered goes first, then each slice of `data` in order, and the
            // last slice is repeated `splat` times. `tap` holds no buffer, so
            // there is nothing to send first for that caller; `tapWith` does.
            self.sink.bytes.appendSlice(gpa, w.buffered()) catch return error.WriteFailed;
            w.end = 0;
            var written: usize = 0;
            for (data[0 .. data.len - 1]) |slice| {
                self.sink.bytes.appendSlice(gpa, slice) catch return error.WriteFailed;
                written += slice.len;
            }
            const last = data[data.len - 1];
            for (0..splat) |_| {
                self.sink.bytes.appendSlice(gpa, last) catch return error.WriteFailed;
                written += last.len;
            }
            return written;
        }
    };
};

/// Stands in for `src/run.zig`'s `Printer`: it writes what it is told into the
/// transcript, exactly as that printer does, and it counts the calls it was
/// given.
///
/// **The counts are the point.** The display wraps this observer and must pass
/// every call on unchanged. A stand-in that only wrote bytes could not tell a
/// display that forwarded from one that answered for itself.
const Recorder = struct {
    gpa: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    events: usize = 0,
    pieces: usize = 0,
    notices: usize = 0,

    fn observer(self: *Recorder) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        _ = ev;
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.events += 1;
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.pieces += 1;
        switch (piece) {
            .text => |text| self.bytes.appendSlice(self.gpa, text) catch {},
            .reasoning => {},
        }
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        _ = text;
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.notices += 1;
    }
};

/// A clock a test moves by hand.
///
/// **The suite asserts on no wall clock and this is how it stays that way.** A
/// turn's header says the time and a finished tool call says how long it took,
/// so both are on the screen; a test that read the machine's own clock for
/// either would be a test whose answer depends on when it ran. See `Ui.clock`.
const HandClock = struct {
    at_ms: i64 = 0,

    fn clock(self: *HandClock) chock_core.notices.Clock {
        return .{ .ctx = self, .nowMs = nowMs, .utc_offset_minutes = 0 };
    }

    fn nowMs(ctx: ?*anyopaque) i64 {
        const self: *HandClock = @ptrCast(@alignCast(ctx.?));
        return self.at_ms;
    }
};

/// Everything one headless run of the display needs, with no terminal anywhere.
const Headless = struct {
    gpa: std.mem.Allocator,
    threaded: std.Io.Threaded,
    env: std.process.Environ.Map,
    device: std.Io.File,
    sink: Sink,
    tap: Sink.Tap,
    /// Standard error, kept apart from the frames. A warning is written to the
    /// same terminal in the real program, and that is exactly what makes the
    /// display repaint, but a test that mixed the two could not read either.
    diagnostics: Sink,
    diagnostics_tap: Sink.Tap,
    recorder: Recorder,
    /// The clock the display reads, so no test depends on when it ran.
    hand: HandClock,
    screen: *Ui,
    /// Where `screenText` builds the grid as text. Held here so no test has to
    /// free it, and reused so a test that reads the screen twice allocates once.
    plain: std.ArrayList(u8),
    /// `Ui.stop` frees the display, so taking it down twice is a use after
    /// free. This lets a test that wants to read the bytes teardown itself
    /// wrote call `stop` early and still keep `close` on a `defer`.
    stopped: bool,

    /// A geometry with a round cell, so a failure is about the display and not
    /// about where a glyph rounded to.
    const size = phantom.tui.term.Size{ .cols = 40, .rows = 8, .xpixel = 320, .ypixel = 128 };

    /// Built on the heap because `Ui` keeps the address of `sink`'s tap and of
    /// `transcript`, and a value returned by copy would leave both aimed at the
    /// dead temporary it was copied out of.
    fn open(gpa: std.mem.Allocator) !*Headless {
        return openSized(gpa, size);
    }

    /// The same display on a screen of a stated size. **80 columns is the
    /// design width**, so a test about how a session reads, rather than about
    /// one row, asks for one.
    fn openSized(gpa: std.mem.Allocator, screen: phantom.tui.term.Size) !*Headless {
        const self = try gpa.create(Headless);
        errdefer gpa.destroy(self);

        self.gpa = gpa;
        self.threaded = std.Io.Threaded.init(gpa, .{});
        const io = self.threaded.io();
        self.env = std.process.Environ.Map.init(gpa);
        self.sink = .{ .gpa = gpa };
        self.tap = self.sink.tap();
        self.diagnostics = .{ .gpa = gpa };
        self.diagnostics_tap = self.diagnostics.tap();
        self.stopped = false;

        self.plain = .empty;

        // Never read and never written: the session is given a size, so nothing
        // asks the device anything, and `askForMessage` is not called here.
        self.device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
        errdefer self.device.close(io);
        errdefer tty.useStreams(io, null, null);

        tty.useStreams(io, &self.tap.writer, &self.diagnostics_tap.writer);
        self.screen = try Ui.start(
            gpa,
            io,
            &self.env,
            .{ .terminal = .{ .in = self.device, .out = self.device, .size = screen } },
        );
        // The display comes up showing the message field, and every test below
        // is about a session, so this is where the real flow's `askForMessage`
        // would have left it.
        self.screen.phase = .session;
        // **Before any test says anything**, so nothing a test reads carries
        // the machine's own time. See `HandClock`.
        self.hand = .{};
        self.screen.clock = self.hand.clock();
        self.recorder = .{ .gpa = gpa, .bytes = &self.screen.transcript };
        self.screen.wrap(self.recorder.observer());
        return self;
    }

    /// Where the display's own bytes are. The `Ui` owns them, so a test reads
    /// them through it rather than keeping a second copy.
    fn transcript(self: *Headless) *std.ArrayList(u8) {
        return &self.screen.transcript;
    }

    /// Take the display down, leaving everything it wrote in the sink.
    fn stop(self: *Headless) void {
        if (self.stopped) return;
        self.stopped = true;
        self.screen.deinit();
    }

    fn close(self: *Headless) void {
        const io = self.threaded.io();
        self.stop();
        self.plain.deinit(self.gpa);
        tty.useStreams(io, null, null);
        self.device.close(io);
        self.sink.deinit();
        self.diagnostics.deinit();
        self.env.deinit();
        self.threaded.deinit();
        self.gpa.destroy(self);
    }
};

test "a whole run drives a real session with no terminal, and every frame goes through the standard output writer" {
    // What this pins that no pure function can: the display really starts, it
    // really draws, and not one byte of a frame goes straight to a descriptor.
    // Every byte read below arrived through `tty.writeOut`, because that is the
    // only thing `Frames.drain` calls and this test replaced the stream under
    // it. Mutation check: give `Frames` a writer over the real standard output
    // and the sink comes back empty.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // The alternate screen. This is what says the display really took over, and
    // it is the sequence `test/cli/streams.zig` looks for the absence of in a
    // piped run.
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "\x1b[?1049h") != null);

    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .in_progress },
    };
    const watcher = h.screen.observer();
    watcher.onPiece(.{ .text = "the parser is where it fails\n" });
    watcher.onNotice("waiting out a rate limit");
    watcher.onEvent(1, .{ .plan_update = .{ .steps = &steps } });

    // Every call was passed on to the observer this one wraps. Mutation check:
    // stop forwarding in any one of the three and its count stays at zero.
    try testing.expectEqual(@as(usize, 1), h.recorder.pieces);
    try testing.expectEqual(@as(usize, 1), h.recorder.notices);
    try testing.expectEqual(@as(usize, 1), h.recorder.events);

    // The plan was folded, which is what the panel draws from.
    try testing.expectEqual(@as(usize, 2), h.screen.plan.steps.items.len);

    // And the words and the notice are on the screen. The plan is not a region:
    // a step that moved is a row of the transcript, in Chock's voice.
    //
    // **Read out of the grid and not out of the bytes above.** A frame is a
    // diff: a row drawn over another row sends only the cells that differ, so a
    // word can reach the screen in several pieces and be nowhere in the stream
    // as one string. The grid is what a person sees.
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "the parser is where it fails") != null);
    try testing.expect(std.mem.indexOf(u8, plain.items, "plan step s2 is now in_progress") != null);
    try testing.expect(std.mem.indexOf(u8, plain.items, "waiting out a rate limit") != null);
}

test "the message is typed into the display, and Enter is what says it is the message" {
    // **The message is asked for inside the interface**, in a
    // `phantom.TextField`, and never on a line printed before the display came
    // up. This drives that field with real key events through the real focus
    // manager, so what is pinned is the wiring and not a copy of it.
    //
    // Mutation check: drop the `KeyboardListener` and Enter never submits;
    // drop `on_change` and the message comes back empty.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    // Back to what `Ui.start` really leaves: the field, before any session.
    h.screen.phase = .message;

    // One frame, so there is a tree for the focus manager to walk, and then the
    // field takes the focus exactly as `askForMessage` puts it there.
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    // Typed. The decoder turns these bytes into key events, and the field is
    // what holds them.
    h.screen.surface.terminal.feed("fix the parser");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("fix the parser", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    // And the words are on the screen while they are being typed. One more
    // frame, because `step` draws before it takes input in: the frame that
    // shows a key is the one after the key arrived.
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "fix the parser") != null);

    // Enter, which the field deliberately leaves alone so a caller can say what
    // submitting means.
    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
}

test "a second turn gets a field of its own, and carries nothing of the first one into it" {
    // **The interface is a conversation, not one question.** `src/run.zig` runs
    // a turn, asks again, appends what it is given, and runs another. The state
    // this file holds across that has to be right in both directions: the
    // transcript keeps growing, and the field starts empty.
    //
    // Mutation check: drop the two `clearRetainingCapacity` and `submitted`
    // lines from `beginInput` and the second turn submits the first turn's
    // words the moment it opens.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // Turn one, typed and sent.
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("first\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expectEqualStrings("first", h.screen.typed.items);

    // The turn runs, and the display shows the session while it does.
    h.screen.endInput();
    try testing.expectEqual(Ui.Phase.session, h.screen.phase);
    h.screen.observer().onPiece(.{ .text = "the parser is where it fails\n" });

    // Turn two. Nothing of the first turn is in the field, and nothing is
    // submitted until this turn's own Enter.
    h.screen.beginInput();
    try testing.expectEqual(Ui.Phase.message, h.screen.phase);
    try testing.expectEqualStrings("", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("second");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("second", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);

    // And the transcript is the whole session, not this turn's part of it. It
    // is the log's own bytes and nothing here resets it.
    h.screen.endInput();
    try testing.expectEqualStrings("the parser is where it fails\n", h.transcript().items);
}

test "an empty line ends the conversation, and Ctrl-C at the field ends it too" {
    // **A person must always be able to get out**, and both ways out are named
    // on the screen: see `messageView`. Each of them makes `askForMessage`
    // answer null, which `src/run.zig` reads as the end of the session, so the
    // log gets its `session.end` either way and nothing is lost.
    //
    // Mutation check: make `askForMessage` return an empty message rather than
    // null and a person who pressed Enter on an empty line starts a turn with
    // nothing in it, over and over, with no way out but Ctrl-C.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // Enter on an empty line. The field is submitted and holds nothing.
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("   \r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expect(std.mem.trim(u8, h.screen.typed.items, " \t\r\n").len == 0);

    // Which is what `askForMessage` reads as nothing asked for. Driven through
    // the real thing, so the trim and the answer are the ones that run.
    h.screen.beginInput();
    h.screen.surface.terminal.feed("  \t \r");
    try testing.expectEqual(Ask.done, try h.screen.askForMessage(gpa));

    // And the terminal is out of raw mode afterwards, whichever way it ended,
    // so `src/interrupt.zig` owns Ctrl-C again. See `endInput`.
    try testing.expect(!h.screen.keys.?.raw);
}

test "the transcript is written back to the real screen, byte for byte, after the display goes" {
    // The scrollback promise. A person who watched a session on a terminal has
    // the whole of it in their scrollback afterwards, exactly as a run with no
    // display would have left it.
    //
    // Mutation check: replay before `session.deinit` and the transcript lands
    // on the alternate screen, which the very next byte throws away. The order
    // test below is what catches that.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const words = "one\ntwo\nthree\n";
    h.screen.observer().onPiece(.{ .text = words });
    try testing.expectEqualStrings(words, h.transcript().items);

    // Taken down here, which frees the display and the bytes it owned, so the
    // words are compared against this test's own copy from now on.
    h.stop();

    // The last bytes of everything the terminal saw are the transcript, whole
    // and unchanged.
    try testing.expect(std.mem.endsWith(u8, h.sink.bytes.items, words));

    // And the alternate screen was left before they were written, so they are
    // on the screen the person keeps.
    const left = std.mem.lastIndexOf(u8, h.sink.bytes.items, "\x1b[?1049l").?;
    const replayed = h.sink.bytes.items.len - words.len;
    try testing.expect(left < replayed);
}

test "a line written past every writer makes the next frame paint every cell again" {
    // **`src/interrupt.zig` is the one writer left that this has to cover.** A
    // first Ctrl-C prints its line with a raw write syscall from a signal
    // handler, so no writer in this program sees those bytes and the display
    // cannot know its screen scrolled under it. All the handler may do is add
    // to an atomic, and this is what that add buys.
    //
    // Mutation check: drop the `invalidate` in `Ui.paint` and the second frame
    // below carries no glyph at all, because nothing about the tree changed.
    // Take `tty.noteScroll` out of `src/interrupt.zig`'s handler and the same
    // line fails, which is the corrupted screen a person would be left looking
    // at after one press.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onPiece(.{ .text = "a settled line\n" });
    const settled = h.sink.bytes.items.len;

    // Nothing about the session changed, so an ordinary frame sends nothing.
    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expectEqual(settled, h.sink.bytes.items.len);

    // Exactly what the handler does, and nothing else.
    tty.noteScroll();

    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items[settled..], "a settled line") != null);
}

test "a warning written while the display is up is a row of the transcript and not a line on the screen" {
    // **The fault: it was erased, not hidden.** Standard error points at the
    // real terminal for the whole session, so the warning landed on the
    // alternate screen and the very next frame painted over it. A person acting
    // on `chock:` lines saw them flash and go.
    //
    // Mutation check: never install the writer in `Ui.start` and the first two
    // expectations swap, which is the warning back on a screen that is
    // repainted. Return the row without `emit`'s `transcript` append and the
    // scrollback expectation fails.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // The painter for standard error is decided from the real terminal and is
    // on in a real run, so a warning really does arrive wrapped in SGR bytes.
    defer tty.configure(.{});
    tty.configure(.{ .stderr_is_tty = true, .term = "xterm-256color" });
    try testing.expect(tty.stderrPainter().on);

    tty.print(.warn, "chock: something to act on\n", .{});

    // Not on the real terminal's standard error, which is the screen the
    // display is drawing on.
    try testing.expectEqualStrings("", h.diagnostics.bytes.items);

    // A row of the transcript, in Chock's own voice, because a diagnostic is
    // the harness talking and never the model.
    var said = false;
    for (h.screen.lines.items) |line| {
        if (!std.mem.eql(u8, line.text, "chock: something to act on")) continue;
        said = true;
        try testing.expectEqual(Voice.chock, line.voice);
    }
    try testing.expect(said);

    // And not one byte of escape in it, or `visibleLine` would put a space and
    // then `[33m` into cells nobody chose.
    for (h.screen.lines.items) |line| {
        try testing.expect(std.mem.indexOfScalar(u8, line.text, 0x1b) == null);
        try testing.expect(std.mem.indexOf(u8, line.text, "[33m") == null);
    }

    // And it is in the bytes the display writes back to the real screen, so a
    // person who scrolls up after the session finds it there.
    try testing.expect(std.mem.indexOf(
        u8,
        h.transcript().items,
        "chock: something to act on\n",
    ) != null);
}

test "a diagnostic reaches the real terminal before the display takes it and after it gives it back" {
    // **Phase 1 and phase 3 are unchanged, and that was deliberate.** Phase 1's
    // lines used to land on the alternate screen and be repainted away, which is
    // this same fault in another place, and they were moved in front of the
    // display for exactly that reason. A fix that took them again would undo it.
    //
    // Mutation check: install the writer at the top of `Ui.start` instead of at
    // the end and the first expectation fails; never call `finish` in `Ui.stop`
    // and the last one does, with the line going into a display that has gone.
    // **Built by hand and not with `Headless`.** That helper points standard
    // error at a sink of its own inside the same call that starts the display,
    // so no line can be written between the two, which is exactly the moment
    // this test is about.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var frames: Sink = .{ .gpa = gpa };
    defer frames.deinit();
    var frames_tap = frames.tap();
    // The real terminal's standard error, for the whole of this test.
    var real: Sink = .{ .gpa = gpa };
    defer real.deinit();
    var real_tap = real.tap();

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    const device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
    defer device.close(io);

    defer tty.useStreams(io, null, null);
    tty.useStreams(io, &frames_tap.writer, &real_tap.writer);
    defer tty.configure(.{});
    tty.configure(.{});

    // Phase 1: no display yet, so the line is on the terminal a person is
    // looking at.
    tty.print(.warn, "chock: before the display\n", .{});
    try testing.expectEqualStrings("chock: before the display\n", real.bytes.items);

    const screen = try Ui.start(gpa, io, &env, .{ .terminal = .{
        .in = device,
        .out = device,
        .size = Headless.size,
    } });

    // Phase 2: the display holds the screen, so the real terminal gets nothing
    // more.
    tty.print(.warn, "chock: while the display is up\n", .{});
    try testing.expectEqualStrings("chock: before the display\n", real.bytes.items);

    screen.deinit();

    // Phase 3: the display gave the terminal back with the writer it replaced.
    tty.print(.warn, "chock: after the display\n", .{});
    try testing.expectEqualStrings(
        "chock: before the display\nchock: after the display\n",
        real.bytes.items,
    );
}

test "a diagnostic with no newline at the end is still a row when the display comes down" {
    // Nothing promises a diagnostic ends in a newline, and the last thing
    // written before a display comes down is where a missing one would be. A
    // line held for a newline that never arrives would be a line nobody reads.
    //
    // Mutation check: drop the `held` check in `Diagnostics.finish` and both
    // expectations fail.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    tty.print(.warn, "chock: a line that never ended", .{});
    h.stop();

    try testing.expect(std.mem.endsWith(
        u8,
        h.sink.bytes.items,
        "chock: a line that never ended\n",
    ));
    try testing.expectEqualStrings("", h.diagnostics.bytes.items);
}

test "a diagnostic of several lines is several rows, blank lines included" {
    // A refusal is a paragraph and its blank lines are its structure, so they
    // are rows exactly as a blank line the agent wrote is one.
    //
    // Mutation check: use `endLine` in `Diagnostics.emit` and the blank row
    // between the two sentences is dropped.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    tty.print(.err, "chock: it failed.\n\nTry this instead.\n", .{});

    var first: ?usize = null;
    var last: ?usize = null;
    for (h.screen.lines.items, 0..) |line, at| {
        if (std.mem.eql(u8, line.text, "chock: it failed.")) first = at;
        if (std.mem.eql(u8, line.text, "Try this instead.")) last = at;
    }
    try testing.expect(first != null and last != null);
    // One row between them, and it is the blank one.
    try testing.expectEqual(first.? + 2, last.?);
    try testing.expectEqualStrings("", h.screen.lines.items[first.? + 1].text);
}

test "the sequences a second Ctrl-C writes cover everything a real session writes on the way out" {
    // A second press ends the process where it stands, so no teardown runs and
    // `src/interrupt.zig` has to put the terminal back from a signal handler
    // with one raw write. Its constant is therefore a copy of what phantom
    // does, and a copy drifts.
    //
    // **Measured against a real session and not against a written down list.**
    // Mutation check: take a sequence out of `interrupt.restore_bytes` and this
    // fails; change phantom's own teardown and it fails too, which is the
    // drift this exists to catch.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // Nothing said, so the transcript is empty and everything `stop` writes is
    // the teardown itself.
    try testing.expectEqual(@as(usize, 0), h.transcript().items.len);
    const mark = h.sink.bytes.items.len;
    h.stop();
    const teardown = h.sink.bytes.items[mark..];

    try testing.expect(teardown.len != 0);
    try testing.expect(std.mem.indexOf(u8, interrupt.restore_bytes, teardown) != null);
}

test "a second Ctrl-C writes the restore bytes only while a display is up" {
    // Three escape sequences written into a pipe would be exactly the
    // corruption `src/tty.zig` exists to keep out of one, so it is the display
    // and not the constant that decides whether they are written at all.
    //
    // Mutation check: make `interrupt.restoreBytesIfArmed` return the bytes
    // whatever the flag says and the first and last lines here fail; never
    // disarm in `Ui.stop` and the last one does.
    const gpa = testing.allocator;
    try testing.expect(interrupt.restoreBytesIfArmed() == null);

    const h = try Headless.open(gpa);
    defer h.close();
    try testing.expectEqualStrings(
        interrupt.restore_bytes,
        interrupt.restoreBytesIfArmed().?,
    );

    h.stop();
    try testing.expect(interrupt.restoreBytesIfArmed() == null);
}
test "with no question open the screen is three regions, with the transcript between the bands" {
    // The whole tree, drawn by a real session and read back as text.
    // `writePlain` gives the grid with no escape byte in it, so a failure shows
    // the screen and not a diff of cursor moves.
    //
    // Mutation check: put the input band above the transcript, or give the
    // transcript the whole height, and the block below stops matching.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7",
        .provider = "local",
    });
    // Twelve minutes and four past midnight, on a stopped clock, so the turn
    // header below is the same string wherever and whenever this runs.
    h.hand.at_ms = (12 * 60 + 4) * 60 * 1000;
    h.screen.observer().onPiece(.{ .text = "the parser is where it fails\nand here is a second line\n" });
    h.screen.observer().onNotice("waiting out a rate limit");

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);

    // Eight rows: the header, six of transcript, and the input.
    //
    // **Read the first column.** Chock's rows carry the rail at column 0 and
    // the agent's are indented past it, with nothing of the agent's ever
    // reaching that column. See `Voice`.
    //
    // **The turn opens with a header.** The model and the clock time go at the
    // head of every turn, the model at the left and the time in the right hand
    // column the eye can ignore.
    //
    // **One blank row between the turn and Chock's own block**, which is the
    // rhythm: one blank line between turns, and never two. It is the `gap` row
    // and it belongs to neither voice: see `Ui.startBlock`.
    try testing.expectEqualStrings(
        \\ chock  chock  worktree  glm4.7  local
        \\
        \\  glm4.7 · local                   12:04
        \\  the parser is where it fails
        \\  and here is a second line
        \\
        \\│ waiting out a rate limit
        \\ >
        \\
    , plain.items);
}

test "each region is a surface of its own, and the bands are not the transcript's" {
    // **A region is marked by a change of cell background first**, and the
    // reason is this: phantom ships no border colour and separates surfaces by
    // elevation, so a band is a recess behind the base the session is drawn on.
    //
    // Read out of the grid's own cells rather than out of the escape bytes, so
    // what is pinned is the colour a person sees and not the sequence that
    // happened to carry it.
    //
    // Mutation check: give every band `bg` and the two expectations below fail,
    // which is the flat screen with no region on it at all.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    _ = h.screen.paint();

    const colors = phantom.ColorScheme.tokyoNight();
    const recess = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_dark);
    const base = phantom.backend.cell_grid.Rgb.fromColor(colors.bg);
    const grid = &h.screen.surface.terminal.grid;
    const parts = split(h.screen.rows, h.screen.approvalRows());

    // The header band and the input band are the recess.
    try testing.expectEqual(recess, grid.cellAt(0, 0).?.bg);
    try testing.expectEqual(recess, grid.cellAt(0, h.screen.rows - 1).?.bg);

    // The transcript between them is the base the session is drawn on, and it
    // is a different surface from both.
    try testing.expectEqual(base, grid.cellAt(0, parts.header).?.bg);
    try testing.expect(!std.meta.eql(recess, base));

    // Every row of the transcript, so the band edges are where `split` put them
    // and not one row out.
    var row_index: u16 = parts.header;
    while (row_index < parts.header + parts.transcript) : (row_index += 1) {
        try testing.expectEqual(base, grid.cellAt(0, row_index).?.bg);
    }
}

test "an agent that writes Chock's own words still writes them under no rail, indented" {
    // **The attack the voice rule names.** Nothing stops a model writing prose
    // that imitates the harness, so the split cannot be a matter of wording:
    // the rail and the column are put there by this file, in front of text the
    // agent supplied, and the agent has no way to write before them.
    //
    // Mutation check: give both voices the same prefix, or take the prefix out
    // of `voicedRow`, and the two rows below become indistinguishable, which is
    // a model able to fake an approval.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // The harness saying something, and the model saying the same words.
    h.screen.observer().onNotice("approval needed, git.push");
    h.screen.observer().onPiece(.{ .text = "chock: approval needed, git.push\n" });

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);

    var rows = std.mem.splitScalar(u8, plain.items, '\n');
    var saw_chock = false;
    var saw_agent = false;
    while (rows.next()) |line| {
        if (std.mem.eql(u8, line, "│ approval needed, git.push")) saw_chock = true;
        if (std.mem.eql(u8, line, "  chock: approval needed, git.push")) saw_agent = true;
        // **Nothing the agent wrote begins at column 0**, whatever it says.
        try testing.expect(!std.mem.startsWith(u8, line, "chock:"));
    }
    try testing.expect(saw_chock);
    try testing.expect(saw_agent);
}

test "a long agent line wraps, and no row of it reaches column 0" {
    // **The fault this fixed and the invariant it must not cost.** A long
    // sentence used to be cut at the right edge and the rest of it was gone. It
    // now wraps, and every row of it still sits at the agent's indent: a
    // continuation at column 0 is exactly the shape a long agent message could
    // use to manufacture a row that reads as Chock's.
    //
    // Mutation check: wrap to `cols` instead of to what the voice leaves, and
    // the second row below starts at column 0.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 40, .rows = 12, .xpixel = 320, .ypixel = 192 });
    defer h.close();

    const sentence = "This is an exceptionally well architected project with strong " ++
        "security guarantees and a clean separation of concerns.";
    h.screen.observer().onPiece(.{ .text = sentence });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    const drawn = try screenText(h);
    var rows = std.mem.splitScalar(u8, drawn, '\n');
    var said: std.ArrayList(u8) = .empty;
    defer said.deinit(gpa);
    var wrapped: usize = 0;
    while (rows.next()) |one| {
        if (one.len == 0) continue;
        // The header band and the input band are Chock's own rows, and this is
        // about the agent's.
        if (!std.mem.startsWith(u8, one, Voice.agent.prefix())) continue;
        wrapped += 1;
        if (said.items.len != 0) try said.append(gpa, ' ');
        try said.appendSlice(gpa, std.mem.trim(u8, one, " "));
    }

    // It really did wrap rather than fit.
    try testing.expect(wrapped > 1);
    // And the whole sentence is on the screen, in order, with nothing dropped.
    try testing.expectEqualStrings(sentence, said.items);
}

test "the transcript stops growing at a readable measure, and the other regions do not" {
    // On a very wide display the transcript stops growing at a readable
    // measure, and a line never runs to 200 columns. The header is facts in a
    // row rather than prose, so it keeps every column there is.
    //
    // Mutation check: return `screenRoom` from `transcriptRoom` and the row
    // below runs the whole width of a very wide display.
    const gpa = testing.allocator;
    const wide: u16 = 200;
    const h = try Headless.openSized(gpa, .{
        .cols = wide,
        .rows = 10,
        .xpixel = wide * 8,
        .ypixel = 160,
    });
    defer h.close();

    // A character grid, so one cell is one step and the widths below can be
    // read as column counts.
    const cell = h.screen.measure.step();
    try testing.expectEqual(@as(f32, wide) * cell, h.screen.screenRoom().width);
    try testing.expectEqual(@as(f32, readable_columns) * cell, h.screen.transcriptRoom().width);
    try testing.expect(h.screen.agentRoom().width < @as(f32, wide) * cell);

    h.screen.observer().onPiece(.{ .text = "word " ** 120 });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |one| {
        if (!std.mem.startsWith(u8, one, Voice.agent.prefix())) continue;
        try testing.expect(columnsOf(one) <= readable_columns);
    }
}

test "a blank line the agent wrote is a blank row at the agent's indent" {
    // **"Even when the LLM uses newlines."** A model writing a structured
    // answer puts a blank line between its sections, and a row builder that
    // dropped an empty line turned the answer into one paragraph.
    //
    // **It is the agent's own content and not the break between two blocks.**
    // See `Line.gap`: only `startBlock` makes one of those, so nothing an agent
    // writes can produce the row that separates its words from Chock's.
    //
    // Mutation check: close a newline with `endLine` instead of `endRow` and
    // the blank row disappears, leaving two sections run together.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onPiece(.{ .text = "first section\n\nsecond section\n" });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });

    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqualStrings("first section", h.screen.lines.items[0].text);
    try testing.expectEqualStrings("", h.screen.lines.items[1].text);
    try testing.expectEqualStrings("second section", h.screen.lines.items[2].text);

    // The empty row is the agent's, in the agent's voice, and it is not a gap.
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
    try testing.expect(!h.screen.lines.items[1].gap);
    // Nothing the agent said made a gap row at all.
    for (h.screen.lines.items) |one| try testing.expect(!one.gap);
}

test "the blank row between two blocks is Chock's, and never two of them" {
    // One blank line between turns, and never two. The break is structure, so
    // it carries no voice and no words: an agent that could produce one could
    // produce the separation between its own block and Chock's.
    //
    // Mutation check: drop the `gap` check in `startBlock` and two blocks in a
    // row put two blank rows between them.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onNotice("the first thing");
    // Nothing before it, so the first block opens with no blank row above it.
    try testing.expect(!h.screen.lines.items[0].gap);

    watcher.onNotice("the second thing");
    var gaps: usize = 0;
    var streak: usize = 0;
    var most: usize = 0;
    for (h.screen.lines.items) |one| {
        if (one.gap) {
            gaps += 1;
            streak += 1;
            most = @max(most, streak);
        } else streak = 0;
    }
    try testing.expectEqual(@as(usize, 1), gaps);
    try testing.expectEqual(@as(usize, 1), most);
}

/// A room of `columns` character cells, measured and laid out with a real face.
///
/// **`Room.grid` will not do for a caller that wraps.** Breaking is phantom's,
/// and phantom lays a line out with the face before it breaks it, so the room a
/// wrapping test asks for has to carry one. See `grid_measure`.
fn gridRoom(font: *phantom.text.Font, columns: f32) Room {
    return .{
        .measure = .{
            .metrics = .{ .mono = .{ .advance = 1, .line = 1, .ascent = 0.8 } },
            .dpr = 1,
            .font = font,
            .size = 1,
        },
        .width = columns,
    };
}

test "a wrapped row breaks at a space, and a word with none is broken at the measure" {
    // A break in the middle of a word is a word a person reads twice, and a
    // word longer than the whole measure has nowhere else to break: a path or a
    // hash has no space in it and the alternative is a row past the edge.
    //
    // **Where the break falls is phantom's rule and not this file's**, so what
    // this pins is that Chock asks for it correctly and reads the answer back
    // whole. See `wrapText`.
    //
    // Mutation check: hand `layoutParagraph` a width of zero and the first case
    // below comes back as one row of nineteen characters.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const broken = try wrapText(arena, "the quick brown fox", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 2), broken.len);
    try testing.expectEqualStrings("the quick", broken[0]);
    try testing.expectEqualStrings("brown fox", broken[1]);

    const solid = try wrapText(arena, "x" ** 25, gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 3), solid.len);
    try testing.expectEqualStrings("x" ** 10, solid[0]);
    try testing.expectEqualStrings("x" ** 5, solid[2]);

    // A line that fits is one row and is not touched.
    const short = try wrapText(arena, "fits", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), short.len);
    try testing.expectEqualStrings("fits", short[0]);

    // An empty line is still a row, which is what keeps a blank line the agent
    // wrote on the screen.
    const nothing = try wrapText(arena, "", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), nothing.len);
    try testing.expectEqualStrings("", nothing[0]);

    // A wide glyph is never split: it is two cells to a glyph and a break lands
    // between them, never inside one.
    const wide = try wrapText(arena, "あいうえお", gridRoom(&font, 4));
    try testing.expectEqualStrings("あい", wide[0]);
    for (wide) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));

    // **A glyph wider than the whole measure keeps a row of its own**, and is
    // not dropped. The words are the session, and a measure of one column is a
    // display nobody can read either way.
    const narrow = try wrapText(arena, "あA", gridRoom(&font, 1));
    try testing.expectEqual(@as(usize, 2), narrow.len);
    try testing.expectEqualStrings("あ", narrow[0]);
    try testing.expectEqualStrings("A", narrow[1]);
}

test "a control byte and a byte that is not UTF-8 are made safe before a row is broken" {
    // **Phantom gives a run it cannot decode no layout at all**, so one bad
    // byte in a tool's output would lose every row of that line rather than one
    // character of it. And an escape byte that reached a cell would be a
    // sequence this file never composed.
    //
    // Mutation check: hand `layoutParagraph` the raw bytes and the first case
    // below comes back as the whole line unbroken, which is the error path.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bad = try wrapText(arena, "good\xffbad words here", gridRoom(&font, 8));
    for (bad) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));
    try testing.expectEqualStrings("good?bad", bad[0]);
    try testing.expect(bad.len > 1);

    const escaped = try wrapText(arena, "red\x1b[31m now", gridRoom(&font, 40));
    try testing.expectEqual(@as(usize, 1), escaped.len);
    try testing.expect(std.mem.indexOfScalar(u8, escaped[0], 0x1b) == null);
    try testing.expectEqualStrings("red [31m now", escaped[0]);
}

test "a row with something in the right hand column is exactly the width and never past it" {
    // **The same rule as the row above, for the rows the fold added.** A
    // duration, a clock time, or a `show` marker is put after the agent's own
    // words, so it is the piece that can push a row past the edge, and a row
    // past the edge wraps to column 0 where only Chock draws.
    //
    // Mutation check: leave out the cut when the right hand value is wider than
    // the row and the last case below comes back longer than the screen.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The right hand value is against the end, whatever is on the left.
    const short = try spread(arena, "run_command", "18.2s", Room.grid(20));
    try testing.expectEqual(@as(f32, 20), columnsOf(short));
    try testing.expect(std.mem.endsWith(u8, short, "18.2s"));

    // The left is what gives way, because half a duration reads as a different
    // duration.
    const long = try spread(arena, "x" ** 200, "18.2s", Room.grid(20));
    try testing.expectEqual(@as(f32, 20), columnsOf(long));
    try testing.expect(std.mem.endsWith(u8, long, "18.2s"));

    // And a row too narrow even for the right hand value is cut, never left to
    // run past the edge.
    for ([_]f32{ 0, 1, 4, 5 }) |cols| {
        const cut = try spread(arena, "run_command", "18.2s", Room.grid(cols));
        try testing.expect(columnsOf(cut) <= cols);
    }
    // The widest marker this file writes, on the narrowest row the design asks
    // about, at the indent an agent row carries.
    const marker = markerText(false, true);
    const room = Room.grid(narrow_columns - 2);
    const narrow = try spread(arena, "255/255 passed", marker, room);
    try testing.expectEqual(room.width, columnsOf(narrow));
}

test "a plan step reaches the transcript as Chock's own row, with the status spelled out" {
    // **With no sidebar the transcript is the only place the plan is**, so
    // every step of an update keeps its row there. See `foldPlan`, and the test
    // below for what an open sidebar collapses.
    //
    // **The word, not a mark.** A second signal that is not colour is needed,
    // and the status spelled out is one that survives a monochrome terminal, a
    // colourblind reader, and a pasted transcript.
    //
    // Mutation check: record a plan update in the agent's voice and the row
    // moves under the indent, where the agent could have written it.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .in_progress },
    };
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &steps } });

    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    for (h.screen.lines.items) |line| try testing.expectEqual(Voice.chock, line.voice);
    try testing.expectEqualStrings("plan step s1 is now done", h.screen.lines.items[0].text);
    try testing.expectEqualStrings("plan step s2 is now in_progress", h.screen.lines.items[1].text);

    // And the fold itself still happened, which is what a later header count
    // would read.
    try testing.expectEqual(@as(usize, 2), h.screen.plan.steps.items.len);
}

/// A display wide enough for the transcript and the plan beside it.
///
/// **A round cell, so a failure is about the layout and not about where a
/// number rounded.** Eight pixels across and sixteen down, which is the cell
/// every other display test here uses.
fn openWide(gpa: std.mem.Allocator, columns: u16, rows: u16) !*Headless {
    return Headless.openSized(gpa, .{
        .cols = columns,
        .rows = rows,
        .xpixel = columns * 8,
        .ypixel = rows * 16,
    });
}

/// The four steps of the capture this sidebar was built for: one update, four
/// steps, and one of them starting.
const four_steps = [_]chock_proto.event.PlanStep{
    .{ .id = "s1", .subject = "read the fold", .status = .in_progress },
    .{ .id = "s2", .subject = "measure it on Darwin", .status = .pending },
    .{ .id = "s3", .subject = "write the rows", .status = .pending },
    .{ .id = "s4", .subject = "ship it", .status = .pending },
};

test "one update of four steps is four rows with no sidebar and one row with one" {
    // **This is the fault the owner measured.** A single `update_plan` call put
    // four rows in the transcript, one per step, and then a fifth. A list of N
    // steps cost N rows every time any one of them moved, because the
    // transcript was carrying a stream of a thing that has one current state.
    //
    // Mutation check: fold with `foldEvent`'s old body, a row per step whatever
    // the sidebar is doing, and the second count below is four rather than one.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    // Closed. Four steps, four rows, which is what the transcript has to keep
    // while it is the only place the plan is.
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try testing.expectEqual(@as(usize, 4), h.screen.lines.items.len);

    // Open. The same update again, and one row for the whole of it.
    h.screen.togglePlan();
    try testing.expect(h.screen.sidebar_open);
    const before = h.screen.lines.items.len;
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &four_steps } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len - before);

    // And the one row says the two facts a person watching wants: how much is
    // done, and what is being worked on now.
    try testing.expectEqualStrings(
        "plan: 0 of 4 done, now on \"read the fold\"",
        h.screen.lines.items[before].text,
    );
}

test "a step the agent gave up on keeps a row of its own, because that is an event" {
    // **A state belongs in the sidebar and an event belongs in the transcript.**
    // The sidebar says a step is stopped now. Only the transcript can say when
    // it stopped and what else was happening, and `PlanStatus.abandoned` exists
    // exactly so a reader can tell work that was finished from work that was
    // given up.
    //
    // Mutation check: drop the `gave_up` walk in `foldPlan` and the update
    // below is one row, which says a count and never says a step was dropped.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    const before = h.screen.lines.items.len;

    const gone = [_]chock_proto.event.PlanStep{
        .{ .id = "s3", .subject = "write the rows", .status = .abandoned },
    };
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &gone } });
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len - before);
    try testing.expectEqualStrings(
        "plan step s3 was given up: write the rows",
        h.screen.lines.items[before].text,
    );

    // **And only when it moves.** An update that repeats a status the step
    // already had is not a second event, so it writes no second row.
    const again = h.screen.lines.items.len;
    h.screen.observer().onEvent(3, .{ .plan_update = .{ .steps = &gone } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len - again);
}

test "the plan opens beside the transcript at the design width and refuses under it" {
    // **80 columns is the design width and everything must work there.** So
    // that is where a second column becomes affordable, and under it the answer
    // is a refusal rather than a two column layout squeezed into a screen that
    // cannot hold one.
    //
    // **A refusal that left a person with no way to read the plan would be
    // worse than the crowded layout.** So the narrow answer writes the plan
    // into the transcript, which is where `/plan` always wrote it.
    //
    // Mutation check: drop the `fitsSidebar` guard in `togglePlan` and the
    // narrow display opens a sidebar and says nothing; return a fixed true from
    // `fitsSidebar` and the same.
    const gpa = testing.allocator;

    // One column under the design width.
    {
        const h = try openWide(gpa, 79, 14);
        defer h.close();
        try testing.expect(h.screen.paint());
        try testing.expect(!h.screen.fitsSidebar());

        h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
        const before = h.screen.lines.items.len;
        h.screen.togglePlan();
        try testing.expect(!h.screen.sidebar_open);
        try testing.expectEqual(@as(f32, 0), h.screen.sidebarWidth());
        try testing.expectEqualStrings(
            "there is no room beside the transcript. A wider display keeps the plan there.",
            h.screen.lines.items[before].text,
        );
        // And the plan itself followed, so nobody is left without it.
        try testing.expectEqualStrings(
            "plan: 0 done, 4 left",
            h.screen.lines.items[before + 1].text,
        );
    }

    // At the design width exactly.
    {
        const h = try openWide(gpa, 80, 14);
        defer h.close();
        try testing.expect(h.screen.paint());
        try testing.expect(h.screen.fitsSidebar());

        h.screen.togglePlan();
        try testing.expect(h.screen.sidebar_open);
        try testing.expectEqual(@as(f32, sidebar_columns * 8), h.screen.sidebarWidth());
        // The transcript keeps everything the sidebar did not take, and the two
        // together are the display. Nothing is lost between them.
        try testing.expectEqual(
            h.screen.width,
            h.screen.transcriptBandRoom().width + h.screen.sidebarWidth(),
        );
    }
}

test "the plan sidebar is drawn beside the transcript and no transcript row reaches it" {
    // **The one way a two column layout goes wrong.** A row cut to the display
    // rather than to the band it is drawn in runs under the region beside it,
    // and what a person sees is a row that stops with no sign it was cut. This
    // is the horizontal twin of the fault `Rows` fixed downwards.
    //
    // Mutation check: cut the transcript's own rows against `screenRoom` by
    // making `transcriptRoom` read it again, and the `x` check below finds the
    // agent's row inside the sidebar's columns.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    // A row far longer than any measure, in a letter nothing else on the screen
    // uses, so where it reaches can be read straight off the grid. Upper case,
    // because `next` and `unknown` are on the screen and both hold an `x`.
    var long: [400]u8 = undefined;
    @memset(&long, 'X');
    h.screen.say(.agent, &long);
    h.screen.endLine();
    try testing.expect(h.screen.paint());

    // 100 columns, 26 of them the sidebar's.
    const kept: usize = 100 - sidebar_columns;
    var lines = std.mem.splitScalar(u8, try screenText(h), '\n');
    var found_side = false;
    var drawn: usize = 0;
    while (lines.next()) |line| {
        // Every `X` is in the transcript's own columns and none is past them.
        if (std.mem.indexOfScalar(u8, line, 'X')) |at| {
            try testing.expect(at < kept);
            try testing.expect(std.mem.lastIndexOfScalar(u8, line, 'X').? < kept);
        }
        drawn += std.mem.count(u8, line, "X");
        // And the sidebar's own rows start where the transcript stops. Read
        // from `kept` on, because the transcript says the same words in its own
        // one row about the update.
        if (line.len <= kept) continue;
        if (std.mem.indexOf(u8, line[kept..], "read the fold") != null) found_side = true;
    }
    try testing.expect(found_side);

    // **Every one of the 400 is on the screen**, which is the check the columns
    // above cannot make on their own. The sidebar's own surface is painted
    // after the transcript, so a row cut to the display rather than to the band
    // is not drawn past the edge: it is covered, and the grid then shows a row
    // that simply stops. Counting what survived is what tells the two apart.
    try testing.expectEqual(@as(usize, long.len), drawn);

    // The sidebar reads the fold and shows every step of it, in its own
    // columns, each with the word its status says. Nothing here rests on a
    // colour, which no fact may do, and phantom's `Icon` would break it
    // outright, because `backend/tui_cells.zig` draws every icon with no cell
    // glyph as one solid block.
    var side: std.ArrayList(u8) = .empty;
    defer side.deinit(gpa);
    var each = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (each.next()) |line| {
        if (line.len <= kept) continue;
        try side.appendSlice(gpa, line[kept..]);
        try side.append(gpa, '\n');
    }
    for ([_][]const u8{
        "plan",
        "0/4 done",
        "read the fold",
        // Cut at the region's own edge, which is 26 characters, and not at the
        // display's.
        "measure it on Dar",
        "write the rows",
        "ship it",
        // Spelled out here rather than read from `statusWord`, so a status that
        // lost its own word to another cannot pass this by agreeing with
        // itself.
        "now     read",
        "next    measure",
    }) |one| {
        try testing.expect(std.mem.indexOf(u8, side.items, one) != null);
    }
    try testing.expect(std.mem.indexOf(u8, side.items, "measure it on Darwin") == null);

    // **A subject longer than the region, cut by the region and not by the
    // display.** A row cut to the display would be laid out to the far side of
    // the screen from a starting point already three quarters across it, so it
    // reaches well past the edge and its end exists nowhere a person can read.
    const wordy = [_]chock_proto.event.PlanStep{.{
        .id = "s5",
        .subject = "a subject far longer than any sidebar could hold, and then some",
        .status = .pending,
    }};
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &wordy } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));

    // And no row of the transcript's own band reaches the edge the sidebar
    // begins at, which is the stronger form of the same question.
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

test "the display follows the window, and asks the device for nothing it was told" {
    // **The display used to keep its first geometry for the whole run**, so a
    // window a person made narrower left every band, every wrapped row and
    // every region width measured against a window that was no longer there.
    // Two guards had to be crossed for that: see `Ui.followSize`. The plan
    // sidebar made it visible, because a display that never learns its width
    // can never refuse the sidebar for want of room either.
    //
    // Mutation check: drop the `sizeMoved` guard in `followSize` and the first
    // expectation below reports a move where the numbers are the same, which is
    // a full screen clear on every frame; drop the `fixed_size` guard and the
    // display below asks `/dev/null` for a size on every frame.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    // A test states the geometry, so nothing is asked and nothing moves.
    try testing.expect(h.screen.fixed_size);
    const before = h.screen.width;
    try testing.expect(h.screen.paint());
    try testing.expectEqual(before, h.screen.width);

    const at: phantom.tui.term.Size = .{
        .cols = 100,
        .rows = 14,
        .xpixel = 800,
        .ypixel = 224,
    };
    // The same numbers are not a move. A resize clears the screen, so a frame
    // that called it for nothing would repaint the whole display.
    try testing.expect(!sizeMoved(at, at.viewport(), at.dpr()));

    // Fewer columns, more columns, and the same grid on a display with a
    // different cell: each of the three is a move.
    for ([_]phantom.tui.term.Size{
        .{ .cols = 70, .rows = 14, .xpixel = 560, .ypixel = 224 },
        .{ .cols = 150, .rows = 14, .xpixel = 1200, .ypixel = 224 },
        .{ .cols = 100, .rows = 14, .xpixel = 1600, .ypixel = 448 },
    }) |moved| {
        try testing.expect(sizeMoved(moved, at.viewport(), at.dpr()));
    }
}

/// Draw the display on a screen of a stated size, as a resize would.
///
/// **What `followSize` does for a real window**, done by hand, because a test
/// states its geometry and `fixed_size` then keeps the device out of it. See
/// `Ui.followSize`.
fn resizeTo(h: *Headless, columns: u16, rows: u16) !void {
    const one = h.screen.surface.terminalSession().?;
    try one.resize(.{
        .cols = columns,
        .rows = rows,
        .xpixel = columns * 8,
        .ypixel = rows * 16,
    });
    try testing.expect(h.screen.paint());
}

test "a clock pinned to the right hand end is pinned again when the window narrows" {
    // **A row built by padding is fixed to the width it was built at.** The
    // turn header and the `you` header used to be composed once, with the
    // clock pushed over by however many spaces the room had then. A narrower
    // window made that row too long, so it wrapped, and the clock spent the
    // rest of the session on a row of its own with nothing else on it.
    //
    // The value rides on the row now and `Ui.voicedRow` lays it out every
    // frame, which is what the fold marker has always done. See `Line.pinned`.
    //
    // Mutation check: build either header with `spread` again and the clock is
    // no longer on the header's own row after the resize.
    //
    // Mutation check: drop `Shown.pinned` in `showRows` and the clock never
    // reaches the screen at all, at either width.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 16);
    defer h.close();

    // 13:45, so the clock cannot be read as any other number on the row.
    h.hand.at_ms = (13 * 60 + 45) * 60 * 1000;
    h.screen.describe(.{ .model = "glm4.7-flash", .provider = "local" });
    h.screen.saidByUser("fix the parser");
    h.screen.openTurn();
    try testing.expect(h.screen.paint());

    // Both headers carry the clock and neither holds it in its own words.
    for ([_][]const u8{ Ui.said_by_user, "glm4.7-flash" }) |head| {
        var found = false;
        for (h.screen.lines.items) |line| {
            if (!std.mem.startsWith(u8, line.text, head)) continue;
            found = true;
            try testing.expectEqualStrings("13:45", line.pinned);
            try testing.expect(std.mem.indexOf(u8, line.text, "13:45") == null);
        }
        try testing.expect(found);
    }

    // Wide, the transcript stops at the readable measure, so the clock is at
    // that measure's edge and well short of the display's.
    const wide = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), wide.rows);
    try testing.expectEqual(@as(usize, readable_columns), wide.ends_at);

    // Narrower than the measure, so the room really moves. The same two rows
    // still carry the clock, and it is against the new edge.
    try resizeTo(h, 50, 16);
    const narrow = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), narrow.rows);
    try testing.expectEqual(@as(usize, 50), narrow.ends_at);

    // Wider again, because a value that only ever shrank would pass the check
    // above and still be stuck at the narrow edge for the rest of the session.
    try resizeTo(h, 120, 16);
    const back = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), back.rows);
    try testing.expectEqual(wide.ends_at, back.ends_at);

    // **Never on a row of its own**, which is what the fault looked like: a
    // clock with nothing beside it, under the header it belongs to.
    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |line| {
        const words = std.mem.trim(u8, line, " ");
        try testing.expect(!std.mem.eql(u8, words, "13:45"));
    }
}

test "in pixels the right hand value is a run of its own, pinned at the true edge" {
    // **PIXELS mode cannot be driven through tmux**, which carries no kitty
    // graphics, so this is where the proportional face is checked. It is the
    // face the fault matters most in: a real font has no column, so a value
    // placed by counting spaces walks with the letters in front of it, which is
    // the whole reason `Ui.pinnedRow` exists.
    //
    // Mutation check: draw the value into the words with `spread` and there is
    // no run of its own to find, so the first lookup gives null.
    //
    // Mutation check: give `Ui.pinnedRow` the band's width rather than the
    // transcript's and the wide edge is far past the measure the row was cut
    // to.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 140, 16);
    defer h.close();

    // The proportional metrics the pixel backend uses, on a session a test can
    // drive, and one frame so the measure is really the face's.
    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);

    h.hand.at_ms = (13 * 60 + 45) * 60 * 1000;
    h.screen.saidByUser("fix the parser");
    try testing.expect(h.screen.paint());

    // A run of its own, which is what makes it placeable at all: the words in
    // front of it are laid out separately and cannot push it.
    const wide = drawnEdgeOf(h, "13:45") orelse return error.NoClockDrawn;
    const measure = h.screen.transcriptRoom().width * h.screen.measure.ratio();
    // Against that measure, within one of its own glyphs, and never past it.
    // The edge read back is the last glyph's origin, so its own advance is what
    // the gap is.
    const glyph = h.screen.measure.advanceOf('5') * h.screen.measure.ratio();
    try testing.expect(wide <= measure);
    try testing.expect(measure - wide <= glyph * 2);

    // Narrower, and it lands on the new measure rather than where the old one
    // was. Nothing of the row reaches past the band either.
    try resizeTo(h, 60, 16);
    const narrow = drawnEdgeOf(h, "13:45") orelse return error.NoClockDrawn;
    const now = h.screen.transcriptRoom().width * h.screen.measure.ratio();
    try testing.expect(now < measure);
    try testing.expect(narrow < wide);
    try testing.expect(narrow <= now);
    try testing.expect(now - narrow <= glyph * 2);
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

/// Where the drawn run that spells `words` reaches, in canvas space, and null
/// when nothing on the screen spells it.
///
/// **The last glyph's origin and not its far side.** A glyph carries where it
/// starts, so its own advance is what a caller has to allow for.
fn drawnEdgeOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                var spelled: [64]u8 = undefined;
                var at: usize = 0;
                var reach: f32 = 0;
                for (t.glyphs) |glyph| {
                    if (at + 4 > spelled.len) break;
                    at += std.unicode.utf8Encode(glyph.cp, spelled[at..]) catch break;
                    if (glyph.x > reach) reach = glyph.x;
                }
                if (!std.mem.eql(u8, spelled[0..at], words)) continue;
                return t.origin.x + reach;
            },
            else => {},
        }
    }
    return null;
}

/// The drawn rows that end with `clock` once the trailing blanks are off.
const Clocked = struct {
    /// How many there are.
    rows: usize = 0,
    /// The column the furthest of them reaches, counted in characters.
    ends_at: usize = 0,
};

fn clockedRows(h: *Headless, clock: []const u8) !Clocked {
    var out = Clocked{};
    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |line| {
        const drawn = std.mem.trimEnd(u8, line, " ");
        if (!std.mem.endsWith(u8, drawn, clock)) continue;
        // The row has words of its own in front of the clock, so this really is
        // a header and not a clock left standing alone.
        try testing.expect(drawn.len > clock.len);
        // Counted in characters and never in bytes. Chock's rail is one column
        // and three bytes, so a byte count reads every row that carries one as
        // two columns wider than it is.
        const across = std.unicode.utf8CountCodepoints(drawn) catch drawn.len;
        if (across > out.ends_at) out.ends_at = across;
        out.rows += 1;
    }
    return out;
}

test "the help pane over a narrowed transcript is cut to the band and not to the display" {
    // **The pane is pinned over the transcript region, so it is as narrow as
    // that region is.** With the plan beside it that is well short of the
    // display, and a row cut to the display is not drawn past the edge: it is
    // covered by the sidebar's own surface, which is painted after it. So the
    // grid shows a row that stops and says nothing about the words that went.
    //
    // Mutation check: cut the pane's rows with `screenRoom` in `Ui.paneRow`
    // and the last check reports rows reaching well past the band.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 80, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try focusTranscript(h);
    try pressKeys(h, "?");
    try testing.expect(h.screen.pane != null);

    // The pane is really on the screen, and so is the plan beside it.
    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "keys") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0/4 done") != null);

    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
}

test "the lists over a narrowed transcript are cut to the band, and so is the rule" {
    // The other three things drawn inside the transcript's own band: the rule
    // that says what is above, the session picker, and the completion list.
    // Each of them used to cut against the whole display, which was right while
    // the band was the display and is wrong the moment anything is beside it.
    //
    // Mutation check: cut with `screenRoom` in `Ui.bandRow` and the check below
    // reports the picker's own row reaching well past the band.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 80, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });

    // A session named far more widely than the band it is offered in.
    const offered = [_]Resumable{.{
        .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        .words = "a session whose words run far past the band this list is drawn in, and then some more",
    }};
    h.screen.picker = &offered;
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.showsRule());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));

    // And the completion list, which is drawn from the same band.
    h.screen.picker = null;
    h.screen.phase = .message;
    h.screen.typed.clearRetainingCapacity();
    try h.screen.typed.appendSlice(gpa, "/");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expect(h.screen.openCompletions(&slots).len != 0);
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

test "a plan longer than the sidebar shows the work that is left and counts what is not there" {
    // **The window follows the work.** A plan whose first ten steps are done
    // would otherwise fill the region with finished rows and hide the one being
    // worked on, which is the only row a person opened this for.
    //
    // Mutation check: start the window at zero in `planRows` and the first
    // assertion finds a finished step where the running one should be; drop the
    // `hides` row and the last assertion finds no count.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var plan = chock_proto.state.Plan{};
    var ids: [20][8]u8 = undefined;
    var subjects: [20][16]u8 = undefined;
    var steps: [20]chock_proto.event.PlanStep = undefined;
    for (&steps, &ids, &subjects, 0..) |*one, *id, *subject, at| {
        one.* = .{
            .id = std.fmt.bufPrint(id, "s{d}", .{at}) catch "s",
            .subject = std.fmt.bufPrint(subject, "step {d}", .{at}) catch "step",
            .status = if (at < 12) .done else if (at == 12) .in_progress else .pending,
        };
    }
    try plan.apply(arena, .{ .steps = &steps });

    // Six rows: the title, four steps, and the row that says what is not shown.
    const said = try planRows(arena, plan, 6);
    try testing.expectEqual(@as(usize, 6), said.len);
    try testing.expectEqualStrings(" plan   12/20 done", said[0].text);
    try testing.expectEqualStrings(" now     step 12", said[1].text);
    try testing.expectEqual(PlanLine.Tone.now, said[1].tone);
    try testing.expectEqualStrings(" next    step 13", said[2].text);
    try testing.expectEqualStrings(" 12 above, 4 below", said[5].text);
    try testing.expectEqual(PlanLine.Tone.aside, said[5].tone);

    // **Never more rows than the region was given**, at any height, and the
    // title is what a region with one row keeps.
    for (0..8) |rows| {
        const few = try planRows(arena, plan, @intCast(rows));
        try testing.expect(few.len <= rows);
    }
    try testing.expectEqual(@as(usize, 0), (try planRows(arena, plan, 0)).len);
    try testing.expectEqualStrings(" plan   12/20 done", (try planRows(arena, plan, 1))[0].text);

    // A plan with nothing in it says so rather than showing a count of zero
    // that reads as a plan with no progress.
    const none = try planRows(arena, .{}, 4);
    try testing.expectEqual(@as(usize, 1), none.len);
    try testing.expectEqualStrings(" plan   nothing yet", none[0].text);

    // **And the region refuses a row it was not given, whatever it is handed.**
    // `Rows` is the second guard behind the count above: a plan of twenty steps
    // on a region with four rows must draw four, because a row placed past a
    // band is not clipped by it but covered by the band under it.
    //
    // Mutation check: drop the row count check in `Rows.add` and give
    // `planRows` a fixed room, and the sidebar draws well under its own band.
    const h = try openWide(gpa, 100, 8);
    defer h.close();
    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &steps } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));
}

test "the sidebar shows what a replayed log folded, and never a second copy of it" {
    // **A resumed session must read the same as a live one.** The sidebar draws
    // from `Ui.plan`, which is the fold every `plan.update` writes and which
    // `replay` rebuilds from the log. A sidebar with a list of its own could
    // disagree with the log, and nothing would say which was right.
    //
    // Mutation check: keep the rows in a field of the `Ui` written by `foldPlan`
    // and draw from that, and the replayed session below shows nothing, because
    // `replay` folds without saying anything.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.replay(1, .{ .plan_update = .{ .steps = &four_steps } });
    // A replay is folded the way a live event is, so the transcript it rebuilds
    // reads exactly as the one this session would have written: one row here,
    // because the sidebar carries the standing state.
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "plan   0/4 done") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "read the fold") != null);
    try testing.expectEqual(@as(usize, 4), h.screen.plan.steps.items.len);
}

test "a sidebar on a display drawn with a real face keeps every row inside its own band" {
    // **The character grid hides this.** There a column is a cell and a width
    // in characters lands on a cell boundary whatever it is multiplied by. A
    // real face has no column, so the sidebar's width, the room its rows are
    // cut to and the room the transcript is left have to be the same three
    // numbers or the regions overlap. PIXELS mode cannot be driven through
    // tmux, which carries no kitty graphics, so this is where it is checked.
    //
    // Mutation check: cut the sidebar's rows against `screenRoom` in
    // `sidebarRows` and the `holds` check fails; size the band in
    // `middleRegions` with `sidebar_columns` unscaled and the widths no longer
    // add up to the display.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 180, 20);
    defer h.close();

    // The proportional metrics the pixel backend uses, on a session a test can
    // drive, and one frame so the measure is really the face's.
    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.fitsSidebar());

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    var said: usize = 0;
    while (said < 30) : (said += 1) {
        h.screen.say(.agent, "a row of the agent's own words, long enough to wrap more than once\n");
    }
    try testing.expect(h.screen.paint());

    // A real face, and not the nominal cell.
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);
    try testing.expect(h.screen.sidebarWidth() > 0);

    // Nothing under its band, which is what `Rows` gives, and the sidebar is
    // one more region that has to obey it.
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    // The three widths agree: nothing reaches past the display, the
    // transcript's rows fit what the sidebar left it, and the two rooms are the
    // display. A subject far too long for the region is what makes the first of
    // those a real question.
    const wordy = [_]chock_proto.event.PlanStep{.{
        .id = "s5",
        .subject = "a subject far longer than any sidebar could hold, and then some",
        .status = .pending,
    }};
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &wordy } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const words = h.screen.roomFor(.agent);
    for (h.screen.showRows(arena)) |one| try testing.expect(words.holds(one.text));
    try testing.expectApproxEqAbs(
        h.screen.width,
        h.screen.transcriptBandRoom().width + h.screen.sidebarWidth(),
        0.001,
    );
}

test "p opens the plan and p closes it, and only while the transcript has the focus" {
    // **`?` and `/help` set the convention**, one letter with the transcript
    // focused and a command that does the same thing, so `p` and `/plan` follow
    // it. A letter answered here and not in `onSessionKey` is a letter that
    // stays a letter while a person is typing a message.
    //
    // Mutation check: answer `p` in `onSessionKey` instead and the last check
    // below finds the sidebar opening while the message field holds the focus,
    // which loses the letter out of the message.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try focusTranscript(h);

    try pressKeys(h, "p");
    try testing.expect(h.screen.sidebar_open);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") != null);

    try pressKeys(h, "p");
    try testing.expect(!h.screen.sidebar_open);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") == null);

    // With the field focused the letter is a letter. `beginInput` puts the
    // focus back where a person typing has it.
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try pressKeys(h, "p");
    try testing.expect(!h.screen.sidebar_open);
    try testing.expectEqualStrings("p", h.screen.typed.items);
}

test "Tab moves the focus between the two regions, and the field starts with it" {
    // **Focus is a security surface**: a key means what the focused region says
    // it means. So a person must be able to see where it is and move it, and it
    // must start somewhere sensible.
    //
    // Driven through phantom's own focus manager with real key events, so what
    // is pinned is the wiring and not a copy of it.
    //
    // Mutation check: focus the first region rather than the last in
    // `Surface.focusLast` and a person cannot type the moment the display is
    // up, because the transcript takes their letters instead.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try testing.expect(!h.screen.transcript_focused);

    // Typing goes to the field, not to the transcript.
    h.screen.surface.terminal.feed("gg");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("gg", h.screen.typed.items);

    // Tab hands the keyboard to the transcript. Phantom's traversal rules are
    // what answer Tab, before any listener sees it.
    h.screen.surface.terminal.feed("\t");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);

    // And now the same letter is a command rather than a letter.
    h.screen.scroll_back = 3;
    h.screen.surface.terminal.feed("g");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);
    try testing.expectEqualStrings("gg", h.screen.typed.items);
}

test "the arrows scroll the transcript from either region, and stop at both ends" {
    // The arrows belong to the session rather than to a region, and the message
    // field declines them, so they reach the session listener whichever region
    // holds the focus. That is what makes them usable while typing.
    //
    // Mutation check: drop the clamp in `scrollBy` and a held arrow runs past
    // the oldest row into rows that are not there.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    // Up, with the field focused: the transcript moves and the field is
    // untouched.
    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
    try testing.expectEqualStrings("", h.screen.typed.items);

    // Down again.
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    // The bottom is a floor: down at the newest row goes nowhere.
    h.screen.surface.terminal.feed("\x1b[B\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    // And the top is a ceiling: far more presses than there are rows stops at
    // the oldest one that is kept.
    const most = h.screen.maxScrollBack();
    try testing.expect(most > 0);
    var press: usize = 0;
    while (press < most + 8) : (press += 1) h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(most, h.screen.scroll_back);
}

test "a scrolled transcript says how much is above, and says so before it is scrolled when focused" {
    // **A rule, not a gap.** A count and a line, because a gap or an ellipsis
    // reads as loss and nothing is lost: the whole session is in the log and in
    // the transcript.
    //
    // **And it is how focus is visible**, which it has to be, because focus
    // decides where a keystroke lands.
    //
    // Mutation check: draw the rule always and a session that nobody has
    // scrolled loses a transcript row for a line that says nothing.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    try testing.expect(h.screen.paint());

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "rows above") == null);

    // Scrolled: the rule says how far, and the row it costs comes out of the
    // transcript.
    h.screen.scrollBy(4);
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "4 rows above") != null);

    // Back at the bottom, but focused: the rule stays, because it is what says
    // the transcript has the keyboard.
    h.screen.scroll_back = 0;
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "0 rows above") != null);
}

test "scrolling back shows older rows and not the newest ones" {
    // The point of scrolling at all. Mutation check: ignore `scroll_back` in
    // `visibleRows` and the same rows are shown however far back a person goes.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_][]const u8{ "one\n", "two\n", "three\n", "four\n" }) |said| h.screen.say(.agent, said);

    const bottom = h.screen.visibleRows(arena, 2);
    try testing.expectEqualStrings("three", bottom[0].text);
    try testing.expectEqualStrings("four", bottom[1].text);

    h.screen.scroll_back = 2;
    const back = h.screen.visibleRows(arena, 2);
    try testing.expectEqualStrings("one", back[0].text);
    try testing.expectEqualStrings("two", back[1].text);
}

/// The arguments of the call every test below makes, as a model really sends
/// them.
const a_test_command = "{\"argv\":[\"zig\",\"build\",\"test\"]}";

/// Ask for one tool call and answer it, with `took_ms` between the two.
///
/// **The clock is moved by hand**, so the duration on the row is a number this
/// file chose. See `HandClock`.
fn callAndAnswer(h: *Headless, output: []const u8, is_error: bool, took_ms: i64) void {
    const watcher = h.screen.observer();
    const at = h.hand.at_ms;
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "run_command",
        .arguments = a_test_command,
    } });
    h.hand.at_ms = at + took_ms;
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = output,
        .is_error = is_error,
        .truncated = false,
    } });
}

/// Put the keyboard on the transcript, which is where `Space` and the arrows
/// mean what they are meant to mean.
fn focusTranscript(h: *Headless) !void {
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);
}

test "a tool call's argument is written the way a person reads it" {
    // **The fault the owner reported.** A row that says `run_command
    // {"argv":["zig",...` cut at the edge is the same row for every command,
    // and which command ran is the one thing a person is looking for.
    //
    // Mutation check: give back `arguments` unchanged and every case below
    // becomes JSON again.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The command, as it was run.
    try testing.expectEqualStrings("zig build test", try argumentText(arena, a_test_command));
    // A path, whichever tool carries one.
    try testing.expectEqualStrings("build.zig", try argumentText(arena, "{\"path\":\"build.zig\"}"));
    // `grep`: the pattern leads, because that is what says which search it was.
    try testing.expectEqualStrings("TODO src", try argumentText(
        arena,
        "{\"path\":\"src\",\"pattern\":\"TODO\"}",
    ));
    // **The content of a file being written is not its argument.** A whole
    // file on the row is the same fault by another route.
    try testing.expectEqualStrings("src/main.zig", try argumentText(
        arena,
        "{\"path\":\"src/main.zig\",\"content\":\"one\\ntwo\\nthree\"}",
    ));
    // Nothing is invented for a shape this cannot read: the JSON comes back as
    // it arrived, which is worth more than a wrong reading.
    try testing.expectEqualStrings("not json at all", try argumentText(arena, "not json at all"));
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", try argumentText(arena, "{\"a\":1,\"b\":2}"));
}

test "the one line of a result leads with the exit status and never with the program's own words" {
    // git prints the word error on a line and still succeeds, so the status is
    // authoritative and the text is not.
    //
    // Mutation check: summarise a failed call by its first line alone and the
    // row can no longer tell a command that printed the word error and
    // succeeded from one that failed.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("exit 128 · the sandbox has no network", try summaryText(
        arena,
        "exit status: 128\nthe sandbox has no network\n",
        true,
        false,
    ));
    // A call that worked is summarised by its verdict, which is its last line,
    // and says no "exit 0" that nobody needed.
    try testing.expectEqualStrings("255/255 passed", try summaryText(
        arena,
        "exit status: 0\nBuild Summary: 104/104 steps succeeded\n255/255 passed\n",
        false,
        false,
    ));
    // A note Chock put in front of a tool's own bytes is the fact about the
    // call, so it is the line rather than the first line of the file.
    try testing.expectEqualStrings("62144 bytes, file_hash b6336a843ada84a7", try summaryText(
        arena,
        "[chock: 62144 bytes, file_hash b6336a843ada84a7]\nconst std = @import(\"std\");\n",
        false,
        false,
    ));
    // A truncated result says so in words, and never in silence.
    const cut = try summaryText(arena, "exit status: 0\nfound 4000 matches\n", false, true);
    try testing.expect(std.mem.indexOf(u8, cut, "truncated") != null);
    // And a result with nothing in it says that too.
    try testing.expectEqualStrings("no output", try summaryText(arena, "", false, false));
}

test "a tool result that would fill the transcript is one row, and the whole of it stays one key away" {
    // **The fault this whole change exists for.** A result used to be written
    // into the transcript entire, so two calls made a session unreadable. A
    // result is one line, the fact first, the output behind a marker: 255/255
    // passed is the fact, and 60 KB of build log is not.
    //
    // Mutation check: say `result.output` in `finishCall` instead of folding it
    // and the build log fills the screen, which is what the owner's screenshot
    // showed.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(gpa);
    try output.appendSlice(gpa, "exit status: 0\n");
    var index: usize = 0;
    while (index < 500) : (index += 1) {
        try output.print(gpa, "line {d} of the build log\n", .{index});
    }
    try output.appendSlice(gpa, "255/255 passed\n");

    callAndAnswer(h, output.items, false, 18_200);

    // Two rows for the whole call: what ran, and what came of it.
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);

    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "255/255 passed") != null);
    // Not one row of the log reached the screen.
    try testing.expect(std.mem.indexOf(u8, plain, "of the build log") == null);
    // And the marker says the rest is behind a key rather than gone, which is
    // the difference between a fold and a loss.
    try testing.expect(std.mem.indexOf(u8, plain, "show") != null);
    // The whole of it is still held, up to the bound this file states.
    try testing.expect(h.screen.lines.items[1].fold.?.body.len > 1000);
}

test "a finished call carries the outcome glyph, the tool, its argument and how long it took" {
    // A call that worked gets the glyph and a settled duration, and one that
    // failed gets the glyph and the exit status spelled out. Both are on the
    // call's own row, and the call and its outcome are one row rather than two.
    //
    // **The duration is shown and never asserted against a real clock.** The
    // display measures it because `chock_proto.event.ToolResult` carries none,
    // and the clock it measures with is stated here: see `HandClock`.
    //
    // Mutation check: leave the running row as it was first written and a
    // finished call still says it is running, with no duration anywhere.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);

    const said = h.screen.lines.items[0].text;
    try testing.expect(std.mem.startsWith(u8, said, "\u{2713} "));
    try testing.expect(std.mem.indexOf(u8, said, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, said, "zig build test") != null);
    // The right hand column, which belongs to the time. **Carried on the row
    // and never pasted into its words**, so it is laid out again against
    // whatever edge the row has when it is drawn. See `Line.pinned`.
    try testing.expectEqualStrings("18.2s", h.screen.lines.items[0].pinned);
    try testing.expect(std.mem.indexOf(u8, said, "18.2s") == null);
    // And it reaches the screen, at the right hand end of the row it belongs
    // to. A value carried and never laid out would be a value nobody sees.
    var call_rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    var timed = false;
    while (call_rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "run_command") == null) continue;
        try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, line, " "), "18.2s"));
        timed = true;
    }
    try testing.expect(timed);
    // The glyph a running call carries is gone, so the two states cannot be
    // read as each other.
    try testing.expect(std.mem.indexOf(u8, said, "\u{22ef}") == null);

    // A call that failed takes the other glyph, which has to differ from the
    // one for a timeout as well as from this one.
    const g = try Headless.open(gpa);
    defer g.close();
    callAndAnswer(g, "exit status: 128\nthe sandbox has no network\n", true, 100);
    try testing.expect(std.mem.startsWith(u8, g.screen.lines.items[0].text, "\u{2717} "));
    try testing.expect(std.mem.indexOf(u8, g.screen.lines.items[1].text, "exit 128") != null);
}

test "a result's note is Chock speaking, above the agent's row and under the rail" {
    // **The fault the owner reported on 2026-08-25.** He asked for a page, the
    // policy refused it correctly, and the paragraph on the screen was written
    // to the model: "which you cannot write and the user can. Ask the user".
    // The person watching read a message about themselves in the third person
    // and reported a working refusal as a broken feature.
    //
    // The fix is not a reword. The model still needs that paragraph, or it
    // retries the call or looks for a way round the file it may not write. So
    // a result carries a second sentence for the second reader:
    // `chock_proto.event.ToolResult.note`.
    //
    // **What makes it readable as Chock's is structural and not the words**:
    // the rail and the indent, the same two signals every other pair of voices
    // in this file is told apart by. See `Voice`.
    //
    // Mutation check: say the note in `.agent` in `finishCall` and the voice
    // assertion fails; drop the note row and the first two fail.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 100, .rows = 12, .xpixel = 800, .ypixel = 192 });
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "fetch_url",
        .arguments = "{\"url\":\"https://ziglang.org/\"}",
    } });
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = "refused, which you cannot write and the user can.",
        .is_error = true,
        .truncated = false,
        .note = "add a rule to chock.zon to read ziglang.org.",
    } });

    // Three rows: the call, Chock's sentence, then the agent's own summary.
    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[1].voice);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[1].text, "add a rule") != null);

    // **Chock's sentence is above the agent's**, so a person who acts on the
    // first line they can act on acts on the one written to them.
    try testing.expectEqual(Voice.agent, h.screen.lines.items[2].voice);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[2].text, "you cannot write") != null);

    // And on the screen the two really are told apart: Chock's row carries the
    // rail, and the agent's row is indented past it and carries none. Both
    // fit on one row at this width, so the start of the row is the start of
    // the sentence.
    // The two prefixes, written out here so a change to `Voice.prefix` is a
    // change this test names rather than one it quietly stops checking.
    try testing.expectEqualStrings("\u{2502} ", Voice.chock.prefix());
    try testing.expectEqualStrings("  ", Voice.agent.prefix());

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    var railed = false;
    var indented = false;
    while (rows.next()) |line| {
        if (std.mem.startsWith(u8, line, "\u{2502} add a rule")) railed = true;
        if (std.mem.startsWith(u8, line, "  refused, which you")) indented = true;
    }
    try testing.expect(railed);
    try testing.expect(indented);
}

test "an ordinary result adds no row of Chock's own" {
    // The note is for the call that needs one. A sentence under every result
    // is a sentence nobody reads, which is the same fault as a colour that
    // fires every turn: see `src/tty.zig` on not painting by category.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 100);
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
}

test "a message the person typed is in the transcript, in Chock's voice at column 0" {
    // **A session that showed turn headers, reasoning, tool calls and answers
    // and nothing the person typed could not be read as a conversation**, which
    // is most of what a transcript is for.
    //
    // Chock's voice, because a message did not come from the model, and `Voice`
    // makes that structural: agent content is indented past the rail and never
    // carries one.
    //
    // **The real path**, from a byte on the device to the row: the loop reads
    // the file below, feeds phantom, phantom fills the field and answers Enter,
    // and `answerFor` calls it a message.
    //
    // Mutation check: drop the `saidByUser` call in `askForMessage` and the row
    // is not there at all. Say it in the agent's voice and the rail goes, which
    // puts a person's own words where the model's go.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "fix the parser\r");
    defer h.screen.keys.?.device.in.close(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const asked = try h.screen.askForMessage(arena_state.allocator());
    try testing.expectEqualStrings("fix the parser", asked.message);

    // The words are a row of the transcript, and the row is Chock's.
    var said: ?usize = null;
    for (h.screen.lines.items, 0..) |line, at| {
        if (std.mem.eql(u8, line.text, "fix the parser")) said = at;
    }
    try testing.expect(said != null);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[said.?].voice);
    // And the row above it names who spoke, which is the shape every other
    // block opens with.
    try testing.expect(said.? > 0);
    try testing.expect(std.mem.startsWith(
        u8,
        h.screen.lines.items[said.? - 1].text,
        Ui.said_by_user,
    ));

    // On the screen it really is at column 0, under the rail.
    try testing.expect(h.screen.paint());
    const shown = try screenText(h);
    var rows = std.mem.splitScalar(u8, shown, '\n');
    var found = false;
    while (rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "fix the parser") == null) continue;
        found = true;
        try testing.expect(std.mem.startsWith(u8, line, Voice.chock.prefix()));
    }
    try testing.expect(found);
}

test "a message that arrived on standard input is in the transcript too" {
    // A piped run never opens the field, so its first message never goes
    // through it: `echo "fix the parser" | chock` hands the words over with
    // `prime`. It is still the person's half of the conversation, so the
    // transcript has to hold it, and a scrollback that showed one kind of
    // message and not the other would be worse than one that showed neither.
    //
    // Mutation check: say it only on the typed path and this fails while the
    // test above still passes.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // The display as `start` leaves it for the first message: the field is up
    // and Chock holds the keyboard. `Headless` opens on the session instead,
    // because every other test below is about one.
    holdsTerminal(h);
    h.screen.phase = .message;
    h.screen.prime("read the log and tell me what broke");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const asked = try h.screen.askForMessage(arena_state.allocator());
    try testing.expectEqualStrings("read the log and tell me what broke", asked.message);

    var found = false;
    for (h.screen.lines.items) |line| {
        if (!std.mem.eql(u8, line.text, "read the log and tell me what broke")) continue;
        found = true;
        try testing.expectEqual(Voice.chock, line.voice);
    }
    try testing.expect(found);

    // **And the keyboard is given back**, which a primed message used to skip:
    // a turn that ran with raw mode still on would run with `ISIG` off, and
    // `src/interrupt.zig` could not own Ctrl-C for the whole of it.
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expectEqual(Ui.Phase.session, h.screen.phase);
}

test "a log folded back in puts the words of a finished turn on the screen, and the observer sees none of it" {
    // **A session that was taken up used to open on an empty transcript**, so a
    // resume looked exactly like a fresh start. `replay` is the display's half
    // of the answer, and the two arms that differ from a live event are the two
    // it exists for: an assistant turn whose words never streamed, and a user
    // message the display never wrote because it was another run that sent it.
    //
    // Mutation check: send an assistant message through `onEvent` instead and
    // the turn shows a header with no words under it.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{ .model = "a-model", .provider = "local" });
    const before = h.recorder.events;

    h.screen.replay(1, .{ .message = .{
        .role = .user,
        .content = &.{.{ .text = "fix the parser" }},
    } });
    h.screen.replay(2, .{ .message = .{
        .role = .assistant,
        .content = &.{.{ .text = "the parser is where it fails" }},
    } });

    var said_by_person = false;
    var said_by_model = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "fix the parser")) {
            said_by_person = true;
            // The person's own words are Chock's block, which is where
            // `saidByUser` already puts them.
            try testing.expectEqual(Voice.chock, line.voice);
        }
        if (std.mem.eql(u8, line.text, "the parser is where it fails")) {
            said_by_model = true;
            // And the model's are the agent's, under no rail.
            try testing.expectEqual(Voice.agent, line.voice);
        }
    }
    try testing.expect(said_by_person);
    try testing.expect(said_by_model);

    // **Nothing reached the observer under this one.** It keeps the plain
    // record of this run, and a log that was written by another run is not
    // something this run wrote.
    try testing.expectEqual(before, h.recorder.events);
}

test "a compaction in a log folded back in is the rule row it is live, with the summary behind it" {
    // A resumed session's log holds every compaction the run before it did, and
    // a fold is not a gap and not a `...`, because those read as loss. So a
    // replay has to reach the same row a live event does rather than skipping
    // what it does not recognise.
    //
    // Mutation check: give `replay` an arm of its own for `compaction` that
    // says nothing and both halves below fail.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.replay(7, .{ .compaction = .{
        .from_id = 3,
        .through_id = 40,
        .summary = "the parser was rewritten",
        .kept_ranges = &.{},
        .model_alias = "a-model",
    } });

    var folded = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.indexOf(u8, line.text, "events 3 to 40 folded") == null) continue;
        folded = true;
        // Chock folded the context, so Chock is the one that says so, and the
        // summary is one key underneath rather than gone.
        try testing.expectEqual(Voice.chock, line.voice);
        try testing.expectEqual(Fold.Kind.compaction, line.fold.?.kind);
        try testing.expectEqualStrings("the parser was rewritten", line.fold.?.body);
    }
    try testing.expect(folded);
}

test "a log with more turns than the display keeps leaves the newest of them" {
    // **What the bound really does, measured.** A session that ran for an hour
    // replays into a transcript that keeps `kept_lines` rows, and `addLine`
    // drops the oldest to make room. So a very long log costs a fixed amount and
    // opens on the end of the conversation, which is the part a person resuming
    // is looking for.
    //
    // Mutation check: drop the eviction in `addLine` and the row count runs to
    // the length of the log.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const turns = Ui.kept_lines + 50;
    for (0..turns) |at| {
        var buffer: [64]u8 = undefined;
        const said = try std.fmt.bufPrint(&buffer, "turn {d}", .{at});
        h.screen.replay(@intCast(at + 1), .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = said }},
        } });
    }

    try testing.expect(h.screen.lines.items.len <= Ui.kept_lines);

    var has_newest = false;
    var has_oldest = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "turn 0")) has_oldest = true;
        if (std.mem.eql(u8, line.text, "turn 561")) has_newest = true;
    }
    try testing.expect(has_newest);
    try testing.expect(!has_oldest);
}

test "a fold of the log draws no frame, and the first frame after it shows what it wrote" {
    // One frame per replayed event would build and diff a whole screen
    // thousands of times while a person waits at a display that is not up yet.
    // Nothing is lost by not drawing: every event, piece and notice of the live
    // session draws one, and the message field paints while it waits.
    //
    // **A message a person sent is the event that would draw.** `saidByUser`
    // asks for a frame and so does `foldEvent`, which is every arm but the
    // assistant one, so a replay made only of model turns would pass this
    // whatever the flag said.
    //
    // Mutation check: drop the `replaying` check in `Ui.draw` and the first
    // expectation fails, because a replay writes frames.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const quiet = h.sink.bytes.items.len;
    for (0..20) |at| {
        h.screen.replay(@intCast(at * 2 + 1), .{ .message = .{
            .role = .user,
            .content = &.{.{ .text = "a question that came before" }},
        } });
        h.screen.replay(@intCast(at * 2 + 2), .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "a turn that came before" }},
        } });
    }
    try testing.expectEqual(quiet, h.sink.bytes.items.len);

    // And the rows are really there, so this is not passing for a replay that
    // did nothing at all.
    try testing.expect(h.screen.lines.items.len != 0);

    // The first frame after it puts them on the screen.
    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expect(std.mem.indexOf(
        u8,
        h.sink.bytes.items[quiet..],
        "a turn that came before",
    ) != null);
}

test "a device that is not a terminal is never asked for raw mode" {
    // **Measured on Darwin, and it is a build log fault rather than a wrong
    // picture.** `tcgetattr` on something that is not a terminal answers
    // `ENOTTY` on Linux, which Zig knows; on Darwin `/dev/null` answers
    // `ENODEV`, which it does not, so `std.posix.unexpectedErrno` writes a
    // stack trace to standard error before the error is returned. `catch {}`
    // cannot take those bytes back, and `zig build` marks any run step that
    // wrote to standard error, so a suite that passed reads as one that broke.
    //
    // Mutation check: call `enterRaw` without asking and the Darwin run of this
    // suite prints a trace for every test that opens a display.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // The harness draws on `/dev/null`, which is a device and not a terminal.
    try testing.expect(!(h.device.isTty(h.threaded.io()) catch true));
    // So the display came up holding no raw mode and no settings to put back,
    // which is the same outcome as a terminal that refused raw mode.
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(h.screen.keys.?.was == null);
    try testing.expect(h.screen.keys.?.held == null);
    // And it still draws.
    try testing.expect(h.screen.paint());
}

test "a flush of a frame reaches the descriptor and does not stop at the standard output buffer" {
    // **This is what the capability probe needed.**
    // `phantom.tui.Session.init` writes its queries through this writer,
    // flushes it, and then reads the terminal's reply against a budget of about
    // three seconds. `src/tty.zig`'s standard output holds eight kilobytes and
    // the probe runs before any frame is painted, so without a flush here the
    // queries sat in that buffer for the whole budget, nothing could answer
    // them, and every capability came back false. That is a terminal reporting
    // no pixels, no synchronised output and no in band resize when it has all
    // three.
    //
    // Mutation check: take `flush` out of the `Frames` vtable and the last
    // expectation fails, because the bytes are still in the buffer. Give the
    // tap below no buffer and the test says nothing at all, which is why the
    // one in `Headless` could not have caught this.
    const gpa = testing.allocator;
    var sink = Sink{ .gpa = gpa };
    defer sink.deinit();

    // A buffer of its own, exactly as `main` gives standard output one.
    var buffer: [4096]u8 = undefined;
    var held = sink.tapWith(&buffer);

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    tty.useStreams(io, &held.writer, null);
    defer tty.useStreams(io, null, null);

    var frames = Frames{};
    try frames.writer.writeAll("\x1b[c");
    // Still held back, which is the fault this closes.
    try testing.expectEqual(@as(usize, 0), sink.bytes.items.len);

    try frames.writer.flush();
    try testing.expectEqualStrings("\x1b[c", sink.bytes.items);
}

test "a result's summary sits at the agent's indent and carries no rail" {
    // **A summary is derived from the result, and the result is the agent's
    // text.** So it is agent content, and agent content is indented past column
    // 0 and never carries the rail. A summary that read as Chock speaking would
    // be the harness vouching for bytes a tool produced.
    //
    // Mutation check: say the summary in Chock's voice and the row below moves
    // to column 0 under the rail, where an agent's own output would be standing
    // in for the harness.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[0].voice);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);

    const plain = try screenText(h);
    var rows = std.mem.splitScalar(u8, plain, '\n');
    var found = false;
    while (rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "255/255 passed") == null) continue;
        found = true;
        try testing.expect(std.mem.startsWith(u8, line, "  "));
        try testing.expect(std.mem.indexOf(u8, line, "\u{2502}") == null);
    }
    try testing.expect(found);
}

test "Space on the focused row opens the result and Space again closes it" {
    // `Space` has one job: expand or collapse the focused thing, which is a
    // tool result, a reasoning block, a compaction, or a subagent. This drives
    // the real key through the real focus manager.
    //
    // Mutation check: open a fold in `sayFolded` rather than leaving it closed
    // and the first read below already holds the log; never toggle in
    // `toggleFocused` and the second one still does.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\nthe first line of the log\n255/255 passed\n", false, 18_200);
    try focusTranscript(h);

    // Closed, which is the default and the whole of the fix.
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") == null);

    // Down takes the newest row that can be opened, and Space opens it. The
    // second paint is the frame that carries the change: a `step` builds and
    // then reads the keyboard, so the key pressed in one frame is drawn in the
    // next.
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") != null);

    // And the same key closes it again, so nothing is one way.
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(!h.screen.lines.items[1].fold.?.open);
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") == null);
}

test "the arrows step the focus between the rows that can be opened" {
    // **Focus reaches a row and not only a region**, because `Space` acts on
    // the focused thing. Nothing in the design says how a row comes to be
    // focused, and this is the answer: inside the transcript the arrows step
    // between the rows that can be opened.
    //
    // Mutation check: leave `cursor` where it is on an arrow and `Space` always
    // opens the same row, whichever one a person walked to.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "read_file",
        .arguments = "{\"path\":\"build.zig\"}",
    } });
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = "[chock: 12 bytes]\nthe older body\n",
        .is_error = false,
        .truncated = false,
    } });
    callAndAnswer(h, "exit status: 0\nthe newer body\n", false, 100);
    try focusTranscript(h);

    // Nothing is focused until an arrow is pressed, and the first press takes
    // the newest row that can be opened: "the newest thing is lowest".
    try testing.expect(h.screen.cursor == null);
    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    // Row four, and not row three: the blank row `startBlock` puts between the
    // two calls is a row of the transcript like any other.
    try testing.expectEqual(@as(usize, 4), h.screen.cursor.?);

    // Up again steps to the older one, past the two rows that cannot be opened.
    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.cursor.?);

    // And `Space` acts on the row the focus is on, and on no other.
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(!h.screen.lines.items[4].fold.?.open);

    // The oldest is a ceiling: a held key stops there rather than losing the
    // focus off the top.
    h.screen.surface.terminal.feed("\x1b[A\x1b[A\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.cursor.?);
}

test "the model's reasoning is folded to its size and is never dropped" {
    // Reasoning arrives before the text and is usually long, so it gets a size
    // and a marker and it opens. It is never hidden with no trace, because it
    // is part of the turn. It used to be dropped on the floor here.
    //
    // Mutation check: drop the `.reasoning` piece again and the row below is
    // not there at all, which is a turn whose reasoning left no trace.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    watcher.onPiece(.{ .text = "I will run it.\n" });

    // The size on the row and the words behind the marker, in that order: the
    // reasoning row comes before the words of the turn.
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[0].text, "of reasoning") != null);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[0].text, "KB") != null);
    try testing.expectEqualStrings("I will run it.", h.screen.lines.items[1].text);

    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "of reasoning") != null);
    // The reasoning itself is kept and is not on the screen.
    try testing.expect(std.mem.indexOf(u8, plain, "names a test step") == null);
    try testing.expect(h.screen.lines.items[0].fold.?.body.len > 1000);
}

test "a compaction is a rule row saying what was folded, with the summary behind it" {
    // The compaction is a rule, a horizontal line, saying a count and that the
    // log keeps them. It is not a gap and not a `...`, because those read as
    // loss.
    //
    // **Chock's own row, under Chock's rail**, because Chock folded the context.
    // The summary underneath is a model's own words, so it is drawn at the
    // agent's indent like every other folded body.
    //
    // Mutation check: say the old single sentence again and the row no longer
    // says how much was folded or that the log still has it.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onEvent(9, .{ .compaction = .{
        .summary = "the agent read the parser and found the fault in the lexer",
        .from_id = 1,
        .through_id = 41,
        .kept_ranges = &.{},
        .model_alias = "glm4.7",
    } });

    try testing.expectEqual(Voice.chock, h.screen.lines.items[0].voice);
    const said = h.screen.lines.items[0].text;
    try testing.expect(std.mem.startsWith(u8, said, "\u{2500}\u{2500} "));
    try testing.expect(std.mem.indexOf(u8, said, "events 1 to 41 folded") != null);
    try testing.expect(std.mem.indexOf(u8, said, "The log keeps them") != null);

    // On a screen too narrow for the whole row the count and the rule are what
    // survive, because they are what say a fold happened and how big it was.
    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "events 1 to 41 folded") != null);
    // The summary is folded, not shown, and the row that opens it says so.
    try testing.expect(std.mem.indexOf(u8, plain, "found the fault") == null);
    try testing.expect(std.mem.indexOf(u8, plain, "show") != null);
}

test "a session at the design width reads as the design draws it" {
    // **The rhythm, and not one row.** This is about how a long session reads:
    // a turn header, the reasoning folded to a size, the call and its outcome
    // on one row, the fact under it, and the whole of the output behind a
    // marker. This is that card, drawn by the real display.
    //
    // Mutation check: change any one of the parts and this block stops
    // matching, which is what makes it worth having beside the tests that pin
    // each part on its own.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 60, .rows = 10, .xpixel = 480, .ypixel = 160 });
    defer h.close();

    h.screen.describe(.{
        .project = "chock",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &.{.{ .name = "seccomp", .state = .on }},
    });
    h.hand.at_ms = (12 * 60 + 4) * 60 * 1000;

    const watcher = h.screen.observer();
    watcher.onNotice("Chock copied 12 files from your working tree.");
    watcher.onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    watcher.onPiece(.{ .text = "The build file names a test step. I will run it.\n" });
    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);

    // **This is the rhythm the design draws**, and the blank rows are the whole
    // of what it adds to a wall of rows: Chock's block, one blank row, the turn
    // with its reasoning and its words, one blank row, the call with the one
    // line its result came to. Never two blank rows, and none at the very top.
    // See `Ui.startBlock`.
    //
    // **The marker is `\u{25b6}` here and `\u{25b8}` in `markerText`**, and
    // that is not a mistake in either place. `markFor` hands the codepoint the
    // display writes to phantom as `.chevron_right`, and phantom spells that
    // mark with the large triangle for a cell backend. The two triangles are
    // two spellings of one mark, so the row still says what it said.
    try testing.expectEqualStrings(
        \\ chock  chock  glm4.7-flash  local  ✓ seccomp
        \\│ Chock copied 12 files from your working tree.
        \\
        \\  glm4.7-flash · local                                 12:04
        \\  2.1 KB of reasoning                                 ▶ show
        \\  The build file names a test step. I will run it.
        \\
        \\  ✓ run_command  zig build test                        18.2s
        \\  255/255 passed                                      ▶ show
        \\ >
        \\
    , try screenText(h));
}

test "a subagent takes one row and its own turns never appear in this transcript" {
    // The subagent does not inline. One line says it started, what kind, which
    // model, and that it can be opened. Its turns never appear here.
    //
    // Mutation check: say the reason as a row of its own and the parent's own
    // words for spawning a child stand at column 0 under Chock's rail, which is
    // agent text in the one place agent text may never be.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onEvent(4, .{ .session_spawn = .{
        .child_session = "s-2",
        .child_agent_kind = "reviewer",
        .reason = "it reads the test and reports back. It does not write.",
    } });

    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[0].voice);
    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "started a subagent, reviewer") != null);
    // The reason is the parent agent's own words, so it is behind the marker
    // and at the agent's indent when it is opened, never at the rail.
    try testing.expect(std.mem.indexOf(u8, plain, "It does not write") == null);
    try testing.expectEqualStrings(
        "it reads the test and reports back. It does not write.",
        h.screen.lines.items[0].fold.?.body,
    );
}

test "a line whose first word is not a command exactly is a message, paths included" {
    // **The hazard the whole rule exists for.** A message to a coding agent very
    // plausibly starts with a slash: `/home/ross/chock/src/main.zig is broken`
    // is an ordinary thing to type. A "begins with a slash" rule would swallow
    // it and send nothing.
    //
    // Mutation check: match on the first character rather than on the whole
    // first word and every line below becomes a command that does not exist.
    for ([_][]const u8{
        "/home/ross/chock/src/main.zig is broken",
        "/usr/bin/zig is the wrong version",
        "/etc/nix/nix.conf needs a setting",
        "/tmp is full",
        "/planning the release",
        "/help me understand this",
        "/plan the release with me",
        "look at /plan for the list",
        "",
        "no slash at all",
    }) |line| try testing.expect(commandOf(line) == null);

    // And a first word that is a command exactly is one, with or without words
    // after it.
    try testing.expectEqual(Command.plan, commandOf("/plan").?);
    try testing.expectEqual(Command.plan, commandOf("  /plan  ").?);
    try testing.expectEqual(Command.help, commandOf("/help").?);
    try testing.expectEqual(Command.usage, commandOf("/usage").?);
}

test "the completion list opens on a prefix and closes the moment the line stops being one" {
    // **The list is the live proof of the rule above.** A person typing a path
    // watches it close at `/ho`, which is how they see the line is a message
    // without having to remember anything.
    //
    // Mutation check: keep the list open for any line starting with a slash and
    // a path shows a list of commands it will never run.
    var slots: [Command.all.len]Command = undefined;

    try testing.expectEqual(@as(usize, Command.all.len), completions("/", &slots).len);
    try testing.expectEqual(@as(usize, 1), completions("/h", &slots).len);
    try testing.expectEqual(Command.help, completions("/h", &slots)[0]);
    try testing.expectEqual(@as(usize, 1), completions("/pl", &slots).len);

    // The moment it is no longer a prefix, it is a message.
    try testing.expectEqual(@as(usize, 0), completions("/ho", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("/home/ross", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("fix the parser", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("", &slots).len);

    // A command that already has an argument has been chosen, so there is
    // nothing left to complete.
    try testing.expectEqual(@as(usize, 0), completions("/plan now", &slots).len);
}

test "a slash command is answered in the transcript and never becomes a message" {
    // **The property that matters most.** A command is the harness's: no part of
    // the typed line becomes a user message, an event, or anything the model
    // sees. `askForMessage` answering null-for-a-command is what keeps it, and
    // `src/run.zig` is what would otherwise append it to the log.
    //
    // Mutation check: return the line from `askForMessage` instead of running
    // it and `/plan` is sent to the model as a message.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    // Typed and sent. `askForMessage` would return this if it were a message,
    // and the loop in `src/run.zig` would append it to the log.
    h.screen.surface.terminal.feed("/plan\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expectEqualStrings("/plan", h.screen.typed.items);
    try testing.expect(commandOf(h.screen.typed.items) != null);

    // The answer is a Chock row in the transcript, under Chock's rail, and the
    // command itself is nowhere: nothing said `/plan`.
    //
    // **This display is forty columns, so `/plan` refuses the sidebar and
    // writes the plan here instead.** See `togglePlan`. The last row is
    // therefore the plan, and the row above it is why it is here.
    h.screen.runCommand(.plan);
    try testing.expect(h.screen.lines.items.len != 0);
    for (h.screen.lines.items) |line| {
        try testing.expectEqual(Voice.chock, line.voice);
        try testing.expect(std.mem.indexOf(u8, line.text, "/plan") == null);
    }
    try testing.expectEqualStrings(
        "the agent has written no plan",
        h.screen.lines.items[h.screen.lines.items.len - 1].text,
    );
}

test "Enter on an open list runs what is chosen, not the letters that were typed" {
    // A person who typed `/pl` and pressed Enter meant `/plan`. Without this
    // the two letters would go to the model as a message.
    //
    // Mutation check: drop the completion in `onMessageKey` and `typed` stays
    // at `/pl`, which `commandOf` reads as a message.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("/pl");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 1), h.screen.openCompletions(&slots).len);

    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("/plan", h.screen.typed.items);
    try testing.expectEqual(Command.plan, commandOf(h.screen.typed.items).?);
}

test "the arrows move through the list while it is open, and scroll the transcript when it is not" {
    // **The focus rule, in the one place two regions want the same key.** The
    // list belongs to the input region, so a person typing into it moves
    // through their own list. That is a security property: a keystroke must
    // land where the focus is and never in a neighbour.
    //
    // Mutation check: scroll whatever the list says and typing `/` then `down`
    // moves the transcript under a person who is choosing a command.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    // With the list open, the arrows are the list's.
    h.screen.surface.terminal.feed("/");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.completion_selected);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    // Typing on is what puts the list away: one more character that no command
    // starts with, and it closes. There is no dismiss key, and `onSessionKey`
    // says why.
    h.screen.surface.terminal.feed("z");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 0), h.screen.openCompletions(&slots).len);
    try testing.expectEqualStrings("/z", h.screen.typed.items);

    // And now the same key scrolls, because there is no list to take it.
    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
}

test "the question mark opens the same pane the command does, and only where it is not a letter" {
    // Every key has to be reachable. With the field focused `?` is a character
    // a person is typing, so it reaches the pane only from the transcript,
    // exactly as `g` does.
    //
    // Mutation check: answer `?` from the session listener instead and a person
    // typing a question into the field gets a pane over their session.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    // Typed into the field, it is a character.
    h.screen.surface.terminal.feed("?");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("?", h.screen.typed.items);
    try testing.expect(h.screen.pane == null);

    // With the transcript focused, it is the pane.
    h.screen.surface.terminal.feed("\t?");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);
    try testing.expect(h.screen.pane != null);
    try testing.expectEqual(Pane.Kind.keys, h.screen.pane.?.kind);

    // **The transcript is not where it went.** A pane is a surface over the
    // session, so the session's own record has nothing of it: the rows are the
    // fault this replaced.
    try testing.expectEqual(@as(usize, 0), h.screen.lines.items.len);

    // The same key closes it again, which is what the pane says it does.
    h.screen.surface.terminal.feed("?");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.pane == null);

    // `/help` is the same act, so a person who typed it and a person who
    // pressed the key are looking at the same thing.
    h.screen.runCommand(.help);
    try testing.expect(h.screen.pane != null);
    try testing.expectEqual(Pane.Kind.keys, h.screen.pane.?.kind);
    try testing.expectEqual(@as(usize, 0), h.screen.lines.items.len);
}

/// One row of the pane exactly as it reaches the screen: a column of margin,
/// cut to the width, and with the padding the grid drops off the end of a row
/// taken off too.
fn paneRowAsDrawn(
    arena: std.mem.Allocator,
    h: *Headless,
    words: []const u8,
) ![]const u8 {
    const cut = try visibleLine(
        arena,
        try std.fmt.allocPrint(arena, " {s}", .{words}),
        h.screen.screenRoom(),
    );
    return std.mem.trimEnd(u8, cut, " ");
}

test "the pane can be read in full on a screen far too short for it" {
    // **What the fault was**: the whole answer was drawn at once, so a screen
    // with room for four rows showed four and the rest was off the bottom with
    // no way back to it. Every row must be reachable at a height where almost
    // none of them fit at a time.
    //
    // Mutation check: drop the `hold` and `move` clamps and the last rows are
    // either never reached or scrolled past into blank rows.
    const gpa = testing.allocator;
    // Eight rows: a header, an input line, and six for the transcript, of which
    // the pane spends two on its title and its count.
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const all = try Ui.helpRows(arena_state.allocator());
    try testing.expect(all.len > 8);

    h.screen.openHelp();
    try testing.expect(h.screen.paint());

    // Press down until the pane stops moving, and collect every row seen on the
    // way. Bounded well past the row count so a pane that never stops fails
    // here rather than running for ever.
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(gpa);
    var presses: usize = 0;
    while (presses < all.len * 2) : (presses += 1) {
        try seen.appendSlice(gpa, try screenText(h));
        const before = h.screen.pane.?.at;
        try testing.expect(h.screen.onPaneKey(.{ .keysym = .down }));
        if (h.screen.pane.?.at == before) break;
        try testing.expect(h.screen.paint());
    }

    // Every row of the pane was on the screen at some point, as the pane draws
    // it: one column of margin, and cut to the width like every other row.
    for (all) |one| {
        if (one.len == 0) continue;
        const drawn = try paneRowAsDrawn(arena_state.allocator(), h, one);
        try testing.expect(std.mem.indexOf(u8, seen.items, drawn) != null);
    }

    // And the pane stopped with the last row on the screen rather than scrolled
    // past the end into blank ones.
    const last = try paneRowAsDrawn(arena_state.allocator(), h, all[all.len - 1]);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), last) != null);
}

test "the pane is a surface over the transcript and leaves every other region alone" {
    // The agent has one region and the approval region has a surface and a
    // keyboard of its own. A pane over the transcript must take neither, or an
    // approval could arrive under something a person cannot see past.
    //
    // Mutation check: pin the pane over the whole screen instead of inside the
    // transcript band and the header's own words go missing here.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{ .project = "chock", .model = "a-model" });
    try testing.expect(h.screen.paint());
    const before = try gpa.dupe(u8, try screenText(h));
    defer gpa.free(before);
    try testing.expect(std.mem.indexOf(u8, before, "chock") != null);

    h.screen.openHelp();
    try testing.expect(h.screen.paint());
    const after = try screenText(h);
    // The header band still says what it said.
    try testing.expect(std.mem.indexOf(u8, after, "chock") != null);
    try testing.expect(std.mem.indexOf(u8, after, "a-model") != null);
    // The input band still offers its prompt.
    try testing.expect(std.mem.indexOf(u8, after, ">") != null);
    // And the pane really is drawn.
    try testing.expect(std.mem.indexOf(u8, after, "Esc closes this") != null);
}

test "the pane takes the arrows and the two keys that close it, and refuses the rest" {
    // A pane that swallowed every key would be somewhere a person gets stuck,
    // and one that swallowed none could not be read. Tab belongs to the focus
    // at every moment, so the pane must refuse it.
    //
    // Mutation check: return true from the `else` arm of `onPaneKey` and Tab
    // stops moving the focus while the pane is open.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.openHelp();
    try testing.expect(h.screen.paint());

    try testing.expect(!h.screen.onPaneKey(.{ .keysym = .tab }));
    try testing.expect(!h.screen.onPaneKey(.{ .keysym = .no_symbol, .text = "g" }));
    try testing.expect(h.screen.pane != null);

    try testing.expect(h.screen.onPaneKey(.{ .keysym = .down }));
    try testing.expectEqual(@as(u16, 1), h.screen.pane.?.at);
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .up }));
    try testing.expectEqual(@as(u16, 0), h.screen.pane.?.at);
    // Already at the top, so up does nothing rather than going negative.
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .up }));
    try testing.expectEqual(@as(u16, 0), h.screen.pane.?.at);

    try testing.expect(h.screen.onPaneKey(.{ .keysym = .no_symbol, .text = "?" }));
    try testing.expect(h.screen.pane == null);

    h.screen.openHelp();
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .escape }));
    try testing.expect(h.screen.pane == null);
}

test "a command is never read as a message, and a message that looks like one still is" {
    // **The property that matters most, in the one function that decides it.**
    // `Ui.askForMessage` returns only the `message` arm, so a line this reads as
    // a command never becomes a user message, an event, or anything the model
    // sees.
    //
    // Mutation check: return `.{ .message = trimmed }` for a command and `/plan`
    // is sent to the model; return `.nothing` for one and typing it ends the
    // session.
    try testing.expectEqual(Command.plan, answerFor("/plan").command);
    try testing.expectEqual(Command.help, answerFor("  /help  ").command);
    try testing.expectEqual(Command.usage, answerFor("/usage").command);

    // Every one of these is a message, and a coding agent is asked all of them.
    for ([_][]const u8{
        "/home/ross/chock/src/main.zig is broken",
        "/help me understand this",
        "/plan the release with me",
        "fix the parser",
        "look at /plan",
    }) |line| {
        try testing.expectEqualStrings(
            std.mem.trim(u8, line, " \t\r\n"),
            answerFor(line).message,
        );
    }

    // An empty line is the person saying they are done.
    try testing.expectEqual(Answer.nothing, answerFor(""));
    try testing.expectEqual(Answer.nothing, answerFor("   \t "));
}

test "a session that cannot be taken up says so on its own row, and one that can says nothing" {
    // **Both refusals come from something that already answers them**, so
    // `/resume` and `chock detach` cannot drift apart: `sessions.readinessOf` is
    // the one `chock detach` asks, and `has_work` is the listing's own answer
    // from the walk that produced the row.
    //
    // Mutation check: return an empty refusal for `.running` and a person can
    // choose a session another process is running, which the kernel then
    // refuses from inside a run that has already built a workspace.
    try testing.expectEqualStrings("", Ui.refusalFor(.ready, false));

    // A workspace that still holds work: taking the session up builds a new one
    // from the committed state, so that work would be stranded.
    const kept = Ui.refusalFor(.ready, true);
    try testing.expect(kept.len != 0);
    try testing.expect(std.mem.indexOf(u8, kept, "chock workspace") != null);

    // And every way a session can fail to be adoptable says something.
    for ([_]sessions_cmd.Readiness{
        .running,
        .no_such_session,
        .nothing_to_carry_on,
        .unknown,
    }) |ready| {
        try testing.expect(Ui.refusalFor(ready, false).len != 0);
        try testing.expect(Ui.refusalFor(ready, true).len != 0);
    }
}

test "the picker takes only a session that can be taken, and stays open on one that cannot" {
    // **A refusal is not the end of the picker.** A person who chose a session
    // somebody else is running picks another, without typing the command again.
    //
    // Mutation check: take the refusal arm out of `takePicked` and a session
    // another process owns is handed to `src/run.zig`, which starts a run that
    // the log's own lock then refuses.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const offered = [_]Resumable{
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", .words = "one", .refusal = "another process is running it" },
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAW", .words = "two" },
    };
    h.screen.picker = &offered;
    h.screen.picked = 0;

    // The refused one: said out loud, nothing taken, and the picker is still up.
    h.screen.takePicked();
    try testing.expect(h.screen.taken == null);
    try testing.expect(h.screen.picker != null);
    try testing.expect(!h.screen.submitted);
    try testing.expect(std.mem.indexOf(
        u8,
        h.screen.lines.items[h.screen.lines.items.len - 1].text,
        "another process is running it",
    ) != null);

    // The one that can be taken: taken, and the picker closes.
    h.screen.picked = 1;
    h.screen.takePicked();
    try testing.expectEqualStrings("01ARZ3NDEKTSV4RRFFQ69G5FAW", h.screen.taken.?);
    try testing.expect(h.screen.picker == null);
    try testing.expect(h.screen.submitted);
}

test "the picker takes the arrows before the completion list and before the transcript" {
    // Three things want the arrows and the focus rule decides: the picker is
    // the innermost thing a person is working in, so it takes them first.
    //
    // Mutation check: check the completion list before the picker and a person
    // choosing a session moves an invisible command list instead.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    const offered = [_]Resumable{
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", .words = "one" },
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAW", .words = "two" },
    };
    h.screen.picker = &offered;

    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.picked);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);
    try testing.expectEqual(@as(usize, 0), h.screen.completion_selected);

    // And it stops at the last row rather than running off the end.
    h.screen.surface.terminal.feed("\x1b[B\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.picked);
}

/// A question, as a session that asked to be let out of its own promise would
/// put it. The words in `summary`, `reason` and `detail` are the agent's own,
/// which is what the tests below check the region keeps in its place.
const a_question = Approval{
    .request_id = 7,
    .action = "policy.widen",
    .summary = "let this session out of its own promise about \"git.push\"",
    .reason = "the fix passes here and I want CI to run it",
    .chain = "you \u{25b8} glm4.7-flash \u{25b8} fixer",
    .depth = 2,
    .detail = "+ src/main.zig 3\n- test/slow.zig 12\n",
    .left_ms = 42 * std.time.ms_per_s,
};

/// Put a question up and paint, the way `approval.Display` does.
fn askIn(h: *Headless, one: Approval) !void {
    try testing.expect(h.screen.paint());
    h.screen.showApproval(one);
    takesKeys(h);
    try testing.expect(h.screen.paint());
}

/// Say that this display's device really took raw mode.
///
/// **`/dev/null` will not**, so `takeKeys` left the flag false and the region
/// would draw the row that names `chock approve` instead of the four keys: see
/// `Ui.answersKeys`, and the test that pins that row. A real terminal takes it.
/// Nothing below reads the device: every key goes straight into the phantom
/// session with `feed`, which is where a read would have put it.
fn takesKeys(h: *Headless) void {
    h.screen.keys.?.raw = true;
}

/// Press keys and let the display answer them.
///
/// **Two frames, and that is phantom's own order rather than this file's.** A
/// `step` draws and then reads what has been fed, so the frame that shows what
/// a key did is the one after it. `awaitAnswer` has the same shape: it paints at
/// the top of a look and reads at the bottom, so the next look shows the answer.
fn pressKeys(h: *Headless, keys: []const u8) !void {
    h.screen.surface.terminal.feed(keys);
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.paint());
}

/// Run the settle out, so the region answers keys. See `settle_looks`.
fn settleOut(h: *Headless) !void {
    var left: u8 = settle_looks;
    while (left > 0) : (left -= 1) {
        try testing.expectEqual(Look.waiting, h.screen.awaitAnswer(50));
    }
}

test "the approval region is absent until a question arrives, and it takes the keyboard when it does" {
    // The region is absent when there is no question, so its arrival is itself
    // a signal, and it takes the focus. The second half is a security property:
    // `y` means approve only in the region that has the keyboard.
    //
    // Mutation check: give the region rows with no question and the first
    // expectation fails, which is a band that says nothing when one arrives.
    // Drop the `focusLast` in `showApproval` and the third fails, which is a
    // question nothing can answer.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expectEqual(@as(u16, 0), split(h.screen.rows, h.screen.approvalRows()).approval);
    try testing.expect(!h.screen.approval_focused);

    try askIn(h, a_question);
    try testing.expect(h.screen.approvalRows() != 0);
    try testing.expect(h.screen.approval_focused);

    // And it goes again when the question does, leaving the screen it was on.
    h.screen.clearApproval();
    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expect(!h.screen.approval_focused);
}

test "the region is a raised surface of its own, between the transcript and the input" {
    // That is where it goes, and a region is marked by a change of cell
    // background first, because phantom ships no border colour and separates
    // surfaces by elevation.
    //
    // Mutation check: draw the region on `bg` and the second expectation fails,
    // which is an approval that reads as one more thing in the transcript.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const colors = phantom.ColorScheme.tokyoNight();
    const panel = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_medium);
    const base = phantom.backend.cell_grid.Rgb.fromColor(colors.bg);
    const recess = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_dark);
    try testing.expect(!std.meta.eql(panel, base));
    try testing.expect(!std.meta.eql(panel, recess));

    const parts = split(h.screen.rows, h.screen.approvalRows());
    const grid = &h.screen.surface.terminal.grid;
    var at: u16 = parts.header + parts.transcript;
    while (at < parts.header + parts.transcript + parts.approval) : (at += 1) {
        try testing.expectEqual(panel, grid.cellAt(0, at).?.bg);
    }
    // The input band below it is still its own surface, so the region did not
    // take the line a person types into.
    try testing.expectEqual(recess, grid.cellAt(0, h.screen.rows - 1).?.bg);
}

test "y approves and n refuses, and only after the region has settled" {
    // The two answers are separate letters. And an arriving approval must not
    // steal a keystroke already in flight, so input is ignored for a moment
    // after it appears, which is a security property.
    //
    // Mutation check: answer while the settle count runs and the first
    // expectation below becomes `approved`, which is a person who was leaning
    // on a key at a completion list approving a push with it.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    // A key already in flight, delivered before the region has settled.
    h.screen.surface.terminal.feed("y");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);

    try settleOut(h);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
    try testing.expectEqual(Look{ .answered = .approved }, h.screen.awaitAnswer(50));
    // Taken, so one press is one answer.
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);

    // And `n` is the other answer, on a fresh question.
    h.screen.clearApproval();
    try askIn(h, a_question);
    try settleOut(h);
    try pressKeys(h, "n");
    try testing.expectEqual(Look{ .answered = .refused }, h.screen.awaitAnswer(50));
}

test "Enter and Esc answer nothing, and neither does a letter that is not one of the four" {
    // Twice over: a user who is leaning on Enter to clear a build log must not
    // approve a push by accident, and an approval is not dismissable, because
    // refusing is an answer and ignoring is not.
    //
    // Mutation check: make Enter the default answer and the first block fails,
    // which is the highlighted button the design says must not exist.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);
    try settleOut(h);

    for ([_][]const u8{ "\r", "\n", "\x1b", "q", "Y", "N", " " }) |key| {
        h.screen.surface.terminal.feed(key);
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
        // And the question is still there: nothing dismissed it.
        try testing.expect(h.screen.approval != null);
    }

    // Escape clears the focus in phantom's own traversal rules, before any
    // listener is offered it. The next look takes the focus straight back, so
    // the region a person is being asked in still has the keyboard.
    try testing.expectEqual(Look.waiting, h.screen.awaitAnswer(50));
    try testing.expect(h.screen.approval_focused);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
}

test "d opens the effect at length and w opens the chain, and answering stays available in both" {
    // `d` opens the full diff and `w` opens the spawn chain in full, and
    // answering stays available from inside the diff.
    //
    // Mutation check: leave the keys row out of the open views and the last
    // block fails, which is a person who opened a diff and cannot answer.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const question_high = h.screen.approvalRows();
    try pressKeys(h, "d");
    try testing.expectEqual(Approval.View.diff, h.screen.approval.?.view);
    try testing.expect(h.screen.approvalRows() >= question_high);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "test/slow.zig 12") != null);

    // The same key closes it again, so a person is never stuck in a view.
    try pressKeys(h, "d");
    try testing.expectEqual(Approval.View.question, h.screen.approval.?.view);

    try pressKeys(h, "w");
    try testing.expectEqual(Approval.View.why, h.screen.approval.?.view);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "fixer") != null);

    // Answering from inside a view, which has to stay available.
    try settleOut(h);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
}

test "the region writes its own keys, so nobody has to remember them under a deadline" {
    // This is a rule: an approval shows its own keys in its own region, and a
    // user must never have to remember, or press ? under a deadline.
    //
    // Mutation check: drop the keys row and every expectation below fails.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, approvalKeys(h.screen.screenRoom())) != null);

    // Four keys at every width, and never three: a narrow screen is exactly
    // where a person needs to be told what `w` does.
    for ([_][]const u8{ approval_keys, approval_keys_narrow }) |named| {
        for ([_][]const u8{ "[y]", "[n]", "[d]", "[w]" }) |key| {
            try testing.expect(std.mem.indexOf(u8, named, key) != null);
        }
        try testing.expect(columnsOf(named) <= narrow_columns);
    }
    try testing.expectEqualStrings(approval_keys, approvalKeys(Room.grid(80)));
    try testing.expectEqualStrings(approval_keys_narrow, approvalKeys(Room.grid(50)));

    // And in every view, because a person who opened the diff is the person
    // most likely to be answering.
    h.screen.approval.?.view = .diff;
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(
        u8,
        try screenText(h),
        approvalKeys(h.screen.screenRoom()),
    ) != null);
}

test "a display that cannot take a key says which command answers, and shows no key that does nothing" {
    // **Honest and visible beats a box that silently does nothing.** A window
    // has no device here, and a terminal that refused raw mode has no bounded
    // read, so neither can answer. The question is still in the session log and
    // a client on the approval socket can still answer it, so the region names
    // the command that does.
    //
    // Mutation check: draw the keys row whatever `answersKeys` says and a
    // person presses `y` at a question that will expire under their hand.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.resumable("/tmp/sessions", "01ARZ3NDEKTSV4RRFFQ69G5FAV");

    try testing.expect(h.screen.paint());
    h.screen.showApproval(a_question);
    // And no `takesKeys`: `/dev/null` refused raw mode, which is exactly the
    // case this is about.
    try testing.expect(!h.screen.answersKeys());
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "chock approve") != null);
    // Not one key that would do nothing.
    try testing.expect(std.mem.indexOf(u8, shown, "[y]") == null);
    // The action and the countdown are still there: what changed is the row
    // that says how to answer, and nothing else.
    try testing.expect(std.mem.indexOf(u8, shown, "policy.widen") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0:42") != null);

    // A wide screen names the session as well, and a narrow one leaves the
    // identifier off rather than cutting it, because `chock approve` with no
    // session attaches to the newest session of this project, which is this
    // one, and a cut identifier is a command that names a session nobody has.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const wide = elsewhereText(arena, id, Room.grid(80));
    try testing.expect(std.mem.endsWith(u8, wide, id));
    try testing.expect(columnsOf(wide) <= 80);
    const narrow = elsewhereText(arena, id, Room.grid(40));
    try testing.expect(std.mem.indexOf(u8, narrow, id) == null);
    try testing.expect(std.mem.endsWith(u8, narrow, "chock approve"));
    try testing.expect(columnsOf(narrow) <= 40);
}

test "the four facts that may never drop are on the screen at 80 columns and at 50" {
    // On a screen under 60 columns the action, the reason, the chain, and the
    // deadline never drop.
    //
    // Mutation check: fold the chain into the summary row and the narrow screen
    // loses it, which is "a subagent three levels down asked for this" gone.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "policy.widen") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0:42") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "fixer") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "depth 2") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "the fix passes here") != null);
}

test "the agent's own words stay between the rows Chock owns and cannot reach them" {
    // Nothing stops an agent writing prose that imitates the harness. The
    // region answers that structurally. The agent supplies `summary`, `reason`
    // and `detail` and nothing else, so a summary that spells out the keys row
    // lands on the summary row, indented, and the real keys row is still the
    // last row of the region.
    //
    // Mutation check: put the agent's summary on the first row of the region
    // and the row that says `APPROVAL` is no longer Chock's.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var forged = a_question;
    forged.summary = "APPROVAL  git.push   9:99";
    forged.reason = "[y] approve  [n] refuse";
    try askIn(h, forged);

    var rows: std.ArrayList([]const u8) = .empty;
    defer rows.deinit(gpa);
    const shown = try screenText(h);
    var walk = std.mem.splitScalar(u8, shown, '\n');
    while (walk.next()) |line| try rows.append(gpa, line);

    const parts = split(h.screen.rows, h.screen.approvalRows());
    const first = parts.header + parts.transcript;
    // The region's first row is Chock's, and it names the real action.
    try testing.expect(std.mem.startsWith(u8, rows.items[first], " APPROVAL  policy.widen"));
    // The region's last row is Chock's, and it is the real keys row.
    try testing.expectEqualStrings(
        approvalKeys(h.screen.screenRoom()),
        rows.items[first + parts.approval - 1],
    );
    // The agent's imitations are inside, indented, and reach neither.
    try testing.expect(std.mem.indexOf(u8, shown, "   APPROVAL  git.push") != null);
}

test "a control byte in a diff the agent wrote never reaches a cell" {
    // The same rule the transcript keeps, and for the same reason: the cell
    // writer sends a codepoint straight at the terminal, so an escape byte in a
    // file the agent changed would be an escape sequence this file never
    // composed, at a place on the screen it did not choose.
    //
    // Mutation check: draw a region row without `visibleLine` and the escape
    // byte below is in the cells.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var nasty = a_question;
    nasty.detail = "+ ok\x1b[2J\x1b[H painted over\n";
    try askIn(h, nasty);
    h.screen.approval.?.view = .diff;
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, shown, "painted over") != null);
}

test "the countdown is minutes and seconds, and it never reads as time that is left when none is" {
    // An expiring approval gets a counting number and a position that moves,
    // which are the two signals that are not colour.
    //
    // Mutation check: divide instead of rounding up and a question with 900ms
    // left reads `0:00` while it can still be answered.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("0:42", try countdownText(arena, 42 * std.time.ms_per_s));
    try testing.expectEqualStrings("5:00", try countdownText(arena, 5 * std.time.ms_per_min));
    try testing.expectEqualStrings("0:06", try countdownText(arena, 5_200));
    try testing.expectEqualStrings("0:01", try countdownText(arena, 900));
    // Past the deadline is zero and never a negative number a person would
    // have to read as time.
    try testing.expectEqualStrings("0:00", try countdownText(arena, 0));
    try testing.expectEqualStrings("0:00", try countdownText(arena, -4000));
}

/// Every settings write the display made, in order.
///
/// **A record and not a terminal**, because a test binary has none: `/dev/null`
/// refuses `tcsetattr`, so the real call would say nothing at all about which
/// bits a turn runs with. See `Ui.apply_termios`.
const Settings = struct {
    written: [8]std.posix.termios = undefined,
    count: usize = 0,

    var only: Settings = .{};

    fn apply(
        _: std.posix.fd_t,
        _: std.posix.TCSA,
        settings: std.posix.termios,
    ) std.posix.TermiosSetError!void {
        if (only.count < only.written.len) only.written[only.count] = settings;
        only.count += 1;
    }

    /// The settings the terminal is in now, as far as this record knows.
    fn now() std.posix.termios {
        return only.written[only.count - 1];
    }
};

/// Give this display the terminal a real one would have handed it, and watch
/// what it writes on it.
///
/// **`/dev/null` takes no raw mode**, so `start` found no settings to hold and
/// `takeKeys` has nothing to put on. This is the same stand-in `takesKeys` is
/// for the flag alone, and it states both states as well: `was` is a person's
/// own terminal, echoing and signalling, and `held` is what raw mode makes of
/// it. The display is left holding the keyboard, which is where a turn begins.
fn holdsTerminal(h: *Headless) void {
    Settings.only = .{};

    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ICANON = true;
    was.lflag.ISIG = true;

    var held = was;
    held.lflag.ECHO = false;
    held.lflag.ECHONL = false;
    held.lflag.ICANON = false;
    held.lflag.ISIG = false;

    h.screen.apply_termios = Settings.apply;
    h.screen.keys.?.was = was;
    h.screen.keys.?.held = held;
    h.screen.keys.?.raw = true;
}

test "a turn runs with the echo off, and with the signal key given back" {
    // **The fault a screenshot showed**: `^[[A^[[A^[[A` printed across the
    // transcript while a turn ran. `Term.leaveRaw` puts every bit it saved back
    // at once, `ECHO` among them, so a turn ran with the terminal echoing and a
    // scroll wheel, which a terminal turns into arrow escape sequences while it
    // is on the alternate screen, wrote its bytes on to the screen.
    //
    // **`ISIG` is the half that has to come back**, and only that half: it is
    // what makes a Ctrl-C during a turn a signal at all, so it is what lets a
    // second press reach `chock_core.tools.cancelRunningTool` through
    // `src/interrupt.zig`.
    //
    // Mutation check: write `keys.was` in `giveKeys` instead of `quietOf` it and
    // the first expectation fails, which is the screenshot. Clear `ISIG` in
    // `quietOf` and the third fails, which is a session no Ctrl-C can stop.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    h.screen.endInput();

    try testing.expectEqual(@as(usize, 1), Settings.only.count);
    try testing.expect(!Settings.now().lflag.ECHO);
    try testing.expect(!Settings.now().lflag.ECHONL);
    try testing.expect(Settings.now().lflag.ISIG);
    // And nothing else moved, so the line `src/interrupt.zig` writes from a
    // signal handler still reads as a line.
    try testing.expect(Settings.now().lflag.ICANON);
    try testing.expect(!h.screen.keys.?.raw);

    // The other span, and it never turns the echo on either: the keyboard is
    // taken back for the next message with `ISIG` off and nothing echoing.
    h.screen.takeKeys(.FLUSH);
    try testing.expectEqual(@as(usize, 2), Settings.only.count);
    try testing.expect(!Settings.now().lflag.ECHO);
    try testing.expect(!Settings.now().lflag.ISIG);
    try testing.expect(h.screen.keys.?.raw);
}

test "the terminal is given back exactly as it was found, and only when the display goes" {
    // The echo is off for the display's whole life, so there is one moment at
    // which a person's own shell shows what they type again, and it is the
    // moment the display gives the terminal up. A run that put it back between
    // two turns would be the fault above.
    //
    // Mutation check: put `keys.was` back in `giveKeys` and the first
    // expectation fails. Leave `dropKeys` out of `stop` and the second fails,
    // which is a shell a person has to repair by hand.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    h.screen.endInput();
    try testing.expect(!Settings.now().lflag.ECHO);

    h.stop();
    try testing.expect(Settings.now().lflag.ECHO);
    try testing.expect(Settings.now().lflag.ECHONL);
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(Settings.now().lflag.ICANON);
}

test "only the two bits that echo are taken out of a terminal's own settings" {
    // What a turn runs with is the person's own terminal minus the echo, and
    // never a shape this file composed: `ICANON` and `OPOST` decide how a line
    // written from a signal handler reads, and `ISIG` decides who owns Ctrl-C.
    //
    // **`ECHONL` as well as `ECHO`**, because a terminal in canonical mode
    // echoes a newline through that bit even with `ECHO` off, and a newline
    // moves the whole screen.
    //
    // Mutation check: leave `ECHONL` alone in `quietOf` and the second
    // expectation fails, which is a display that a pressed Enter scrolls.
    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ICANON = true;
    was.lflag.ISIG = true;
    was.lflag.IEXTEN = true;
    was.oflag.OPOST = true;

    const quiet = quietOf(was);
    try testing.expect(!quiet.lflag.ECHO);
    try testing.expect(!quiet.lflag.ECHONL);
    try testing.expect(quiet.lflag.ICANON);
    try testing.expect(quiet.lflag.ISIG);
    try testing.expect(quiet.lflag.IEXTEN);
    try testing.expect(quiet.oflag.OPOST);

    // A person who had the signals off keeps them off: this takes the echo out
    // and never puts anything in.
    var quiet_terminal = was;
    quiet_terminal.lflag.ISIG = false;
    try testing.expect(!quietOf(quiet_terminal).lflag.ISIG);
}

/// Watches what `awaitAnswer` does with a Ctrl-C, without ending the test
/// binary the way a real second press would.
const Raises = struct {
    /// How many times the signal was raised.
    count: usize = 0,
    /// Whether the device was still in raw mode when it was.
    raw_at_raise: bool = false,
    /// The display, so this can read the device's own state at that moment.
    screen: ?*Ui = null,
    /// Which signals were raised, so the test reads what was asked for rather
    /// than trusting the count alone. **The default is one nothing here ever
    /// raises**, so a slot that was never written cannot read as a press.
    signals: [4]std.posix.SIG = @splat(.KILL),

    var only: Raises = .{};

    fn raise(sig: std.posix.SIG) std.posix.RaiseError!void {
        if (only.count < only.signals.len) only.signals[only.count] = sig;
        only.count += 1;
        if (only.screen) |one| {
            if (one.keys) |keys| {
                if (keys.raw) only.raw_at_raise = true;
            }
        }
    }
};

test "a Ctrl-C at a question puts the device back first, and then raises the signal once per press" {
    // **This is the property the project fixed once and must not lose.** Raw
    // mode turns `ISIG` off, so a press arrives as `0x03` and the handler in
    // `src/interrupt.zig` never runs, and it is that handler that ends every
    // running tool call on a second press through
    // `chock_core.tools.cancelRunningTool`. So the display raises the signal
    // itself, and it puts the device back first: a second press ends the
    // process where it stands, with no deferred teardown, and a shell left in
    // raw mode is a shell a person has to repair by hand.
    //
    // Mutation check: raise before `giveKeys` and the second expectation fails,
    // which is that shell. Raise once for a buffer holding two presses and the
    // third fails, which is a person who asked to leave and only asked to stop.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    Raises.only = .{ .screen = h.screen };
    h.screen.raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try askIn(h, a_question);
    // Two presses in one read, which is what a person mashing the key sends.
    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.screen.keys.?.device.in.close(io);

    try testing.expectEqual(Look.canceled, h.screen.awaitAnswer(50));
    // The device is out of raw mode, and it was already out when the signal
    // was raised.
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(!Raises.only.raw_at_raise);
    try testing.expectEqual(@as(usize, 2), Raises.only.count);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[0]);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[1]);
    // And nothing was decided: the question stays open in the log for whoever
    // reconnects, which is the state a crash at the same moment leaves.
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
}

/// A readable file holding `bytes`, so the display's own read really runs.
///
/// **A file and not the device**, because `Headless` draws on `/dev/null`,
/// which never has a byte to read. What is under test is the path from a read
/// to the raise, and that path needs a read that returns something.
fn pressesToRead(tmp: *testing.TmpDir, bytes: []const u8) !std.Io.File {
    const io = testing.io;
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path);
    var name: [std.fs.max_path_bytes + 8]u8 = undefined;
    const file = try std.fmt.bufPrint(&name, "{s}/keys", .{path[0..len]});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, file, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, bytes);
    }
    return std.Io.Dir.openFileAbsolute(io, file, .{});
}

test "a Ctrl-C in an open question is counted as a press and not as a letter" {
    // Raw mode turns `ISIG` off, so a press arrives as `0x03` and no `SIGINT`
    // is sent. `awaitAnswer` puts the device back and raises the signal itself,
    // once for each press this counts, which is what keeps a second press able
    // to end a running tool call through `chock_core.tools.cancelRunningTool`.
    //
    // Mutation check: count only the first press and a person who pressed twice
    // gets one raise, so the press that was meant to leave now only asks.
    try testing.expectEqual(@as(usize, 0), ctrlCPresses("ynd"));
    try testing.expectEqual(@as(usize, 1), ctrlCPresses("\x03"));
    try testing.expectEqual(@as(usize, 1), ctrlCPresses("y\x03n"));
    try testing.expectEqual(@as(usize, 2), ctrlCPresses("\x03\x03"));
    // An escape sequence is not a press: every one a terminal sends starts at
    // `0x1b`, and none of them carries this byte.
    try testing.expectEqual(@as(usize, 0), ctrlCPresses("\x1b[A\x1b[B\x1b[1;5D"));
}

/// The whole screen as text, with no escape byte in it, so a test reads what a
/// person reads. Held in the `Headless` itself, so no caller has to free it.
fn screenText(h: *Headless) ![]const u8 {
    h.plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(h.gpa, &h.plain);
    return h.plain.items;
}

/// A policy that asks a person about everything, so the broker really writes a
/// question and really waits for an answer.
const ask_everything =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

/// What one end to end drive of the broker with a display came back with.
const Drove = struct {
    outcome: ?chock_broker.Broker.Outcome,
    /// The decision of every `approval.response` in the log, as a tag: the
    /// value of an `unknown` borrows from a parse that ends with the replay.
    answers: []std.meta.Tag(chock_proto.event.ApprovalDecision),
    /// Who each answer says gave it.
    responders: [][]const u8,
    questions: usize,
    gpa: std.mem.Allocator,

    fn deinit(self: *Drove) void {
        for (self.responders) |one| self.gpa.free(one);
        self.gpa.free(self.responders);
        self.gpa.free(self.answers);
    }
};

/// Drive a real `Broker` over a real log with `approval.Display` as its waiter,
/// answering with `keys` once the region has settled.
///
/// **One lock, taken once, and the waiter is given that same handle.** That is
/// the arrangement `src/approval.zig`'s own top comment exists to prove, and
/// this drives it with the display in place of the prompt.
fn droveDisplay(
    gpa: std.mem.Allocator,
    io: std.Io,
    h: *Headless,
    keys: []const u8,
) !Drove {
    var backing = try chock_proto.storage.Memory.init(gpa, "01DISPLAYAPPROVAL");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var typist = Typist{ .h = h, .keys = keys };
    var display = approval.Display{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .screen = h.screen,
        .stop = Typist.neverStopped,
    };

    const policy = try chock_policy.table.Table.parse(gpa, ask_everything, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    // The real waiter, wrapped in one that types between two looks. The broker
    // drives `display.waiter()` and nothing here reaches around it.
    typist.inner = display.waiter();
    const broker = chock_broker.Broker{ .policy = policy, .waiter = typist.waiter() };
    const outcome = broker.request(gpa, io, store, &locked, .{
        .action = "policy.widen",
        .summary = "let this session out of its own promise about \"git.push\"",
        .detail = "+ src/main.zig 3\n- test/slow.zig 12\n",
        .reason = "the fix passes here and I want CI to run it",
        .agent_kind = "fixer",
        .model_alias = "main",
        .tool = "restrict_self",
        .tool_call_id = "call1",
        .spawn_chain = &.{.{ .agent_kind = "glm4.7-flash", .reason = "the fix needs a test" }},
        .timeout_ms = chock_broker.Broker.default_timeout_ms,
    }, null);

    var answers: std.ArrayList(std.meta.Tag(chock_proto.event.ApprovalDecision)) = .empty;
    errdefer answers.deinit(gpa);
    var responders: std.ArrayList([]const u8) = .empty;
    errdefer responders.deinit(gpa);
    var questions: usize = 0;
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => questions += 1,
            .approval_response => |response| {
                try answers.append(gpa, std.meta.activeTag(response.decision));
                try responders.append(gpa, try gpa.dupe(u8, response.responder));
            },
            else => {},
        }
    }

    // A fault the waiter could not give back to the broker is a fault a test
    // must not read past. See `approval.Display.failed`.
    if (display.failed) |err| return err;

    return .{
        .outcome = if (outcome) |value| value else |_| null,
        .answers = try answers.toOwnedSlice(gpa),
        .responders = try responders.toOwnedSlice(gpa),
        .questions = questions,
        .gpa = gpa,
    };
}

/// A `Broker.Waiter` that types into the display between two of the real
/// waiter's own looks, and passes every call on to it.
///
/// **Not a stand-in for the waiter under test.** The broker drives
/// `approval.Display` through this, so the log, the deadline, and the answer
/// are all the real thing; this only supplies the keystrokes a person would.
const Typist = struct {
    h: *Headless,
    inner: chock_broker.Broker.Waiter = undefined,
    /// What is typed once the region has settled.
    keys: []const u8,
    looks: usize = 0,

    fn neverStopped() bool {
        return false;
    }

    fn waiter(self: *Typist) chock_broker.Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_broker.Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        const self: *Typist = @ptrCast(@alignCast(ptr));
        return self.inner.nowMs(io);
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) chock_broker.Broker.Waiter.Wake {
        const self: *Typist = @ptrCast(@alignCast(ptr));
        // The region has to be up and settled before a key means anything, so
        // the keys go in only after that many looks have run. See
        // `settle_looks` for why the wait exists. See `takesKeys`: the region
        // is up by now, and its device is `/dev/null`, which will not take raw
        // mode.
        takesKeys(self.h);
        if (self.looks == settle_looks + 1) self.h.screen.surface.terminal.feed(self.keys);
        self.looks += 1;
        return self.inner.wait(io, budget_ms);
    }
};

test "a real broker's question is shown in the region, answered with one key, and the answer reaches the log" {
    // **The whole seam, end to end.** A real `Broker`, a real session log with
    // its exclusive lock held once, `approval.Display` as the waiter, and one
    // keystroke in the region. `src/approval.zig`'s own top comment is what
    // this proves for the display: the answer is appended through the caller's
    // own handle, so there is no second lock and no second open of the log.
    //
    // Mutation check: drop the `record` call in `Display` and the outcome
    // becomes `expired`, which is what every question was before any of this
    // existed.
    const gpa = testing.allocator;
    const io = testing.io;
    const h = try Headless.open(gpa);
    defer h.close();

    var drove = try droveDisplay(gpa, io, h, "y");
    defer drove.deinit();

    try testing.expectEqual(chock_broker.Broker.Outcome.approved_by_user, drove.outcome.?);
    try testing.expect(drove.outcome.?.permits());
    // One question, and exactly one answer: the display's own, and no second
    // one from the broker's deadline.
    try testing.expectEqual(@as(usize, 1), drove.questions);
    try testing.expectEqual(@as(usize, 1), drove.answers.len);
    try testing.expectEqual(
        std.meta.Tag(chock_proto.event.ApprovalDecision).approved_by_user,
        drove.answers[0],
    );
    // And the record says where the answer came from, which is a different
    // fact from a prompt at a bare terminal.
    try testing.expectEqualStrings(approval.display_responder, drove.responders[0]);
    try testing.expect(!std.mem.eql(u8, approval.responder, approval.display_responder));

    // The region is gone once the question is answered, and the device is out
    // of raw mode again, so `src/interrupt.zig` owns Ctrl-C for the rest of the
    // turn.
    try testing.expectEqual(@as(?Approval, null), h.screen.approval);
    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expect(!h.screen.keys.?.raw);
}

test "n in the region is a refusal in the log, and the act does not happen" {
    // The other answer, over the same real broker. **A refusal is an outcome
    // and never an error**, which is what `Broker.Error`'s own doc comment
    // says, so the log carries it as a decision a person made.
    //
    // Mutation check: map `n` to `approved_by_user` and the outcome permits,
    // which is the worst fault this whole region can have.
    const gpa = testing.allocator;
    const io = testing.io;
    const h = try Headless.open(gpa);
    defer h.close();

    var drove = try droveDisplay(gpa, io, h, "n");
    defer drove.deinit();

    try testing.expectEqual(chock_broker.Broker.Outcome.refused_by_user, drove.outcome.?);
    try testing.expect(!drove.outcome.?.permits());
    try testing.expectEqual(
        std.meta.Tag(chock_proto.event.ApprovalDecision).refused_by_user,
        drove.answers[0],
    );
}

test "the chain a person reads begins with them and ends with the agent that asked" {
    // The chain is shown, because "a subagent three levels down asked for this"
    // changes the answer, and it begins with the person: the question is about
    // what the session was asked to do.
    //
    // Mutation check: leave the asking agent off the end and the chain names
    // its parent as the requester.
    const gpa = testing.allocator;
    const said = try approval.chainText(gpa, .{
        .action = "git.push",
        .summary = "",
        .detail = "",
        .reason = "",
        .agent_kind = "fixer",
        .spawn_chain = &.{
            .{ .agent_kind = "glm4.7-flash", .reason = "the fix needs a test" },
            .{ .agent_kind = "reviewer", .reason = "read the test" },
        },
        .timeout_at_ms = 0,
        .tool_call_id = "",
    });
    defer gpa.free(said);
    try testing.expectEqualStrings(
        "you \u{25b8} glm4.7-flash \u{25b8} reviewer \u{25b8} fixer",
        said,
    );

    // A root agent with no parent is one link and still names the person.
    const alone = try approval.chainText(gpa, .{
        .action = "git.push",
        .summary = "",
        .detail = "",
        .reason = "",
        .agent_kind = "main",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "",
    });
    defer gpa.free(alone);
    try testing.expectEqualStrings("you \u{25b8} main", alone);
}

/// How far the display drew past the band a row belonged to, in physical
/// pixels, and zero when nothing did.
///
/// **A band is a surface and then the rows on it.** `Ui.band` paints a
/// `DecoratedBox` over the whole band and then draws its rows inside it, so a
/// frame is a rectangle, the runs that belong to it, the next rectangle, and so
/// on. A run whose top is at or below the rectangle it follows is a row the
/// band never had room for, and the band under it paints over what was drawn
/// there.
/// How far past `limit` the widest run of text on the screen reaches, in the
/// space the canvas is in, and zero when none does.
///
/// **The twin of `drawnPastBands`, across instead of down.** A row too wide for
/// the region it is drawn in is not clipped by that region: with the plan
/// sidebar open it is covered by the sidebar's own surface, which is painted
/// after it, and off the display it is dropped by the backend. Either way the
/// grid shows a row that simply stops, so the fault has to be read out of what
/// was laid out rather than out of what was painted.
///
/// **A run that begins at or past `limit` is not counted**, because that is a
/// row of the region on the other side of the edge and it belongs there. So
/// `limit` can be the display's own edge or the edge between two regions, and
/// the question is the same either way: a row that starts inside a region must
/// end inside it.
///
/// **The last glyph's pen position and not its right edge**, which is short by
/// one advance. That makes this one sided: it never reports a run that fits.
fn drawnPastRight(h: *Headless, limit: f32) f32 {
    var worst: f32 = 0;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                if (t.origin.x >= limit) continue;
                var reach: f32 = 0;
                for (t.glyphs) |glyph| {
                    if (glyph.x > reach) reach = glyph.x;
                }
                const past = t.origin.x + reach - limit;
                if (past > worst) worst = past;
            },
            else => {},
        }
    }
    return worst;
}

/// The right hand edge of the display, in the space the canvas is in.
fn screenEdge(h: *Headless) f32 {
    return h.screen.width * h.screen.measure.ratio();
}

/// The edge between the transcript and the plan sidebar, in the same space.
fn bandEdge(h: *Headless) f32 {
    return h.screen.transcriptBandRoom().width * h.screen.measure.ratio();
}

fn drawnPastBands(h: *Headless) f32 {
    var bottom: f32 = 0;
    var worst: f32 = 0;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .rrect => |r| bottom = r.rect.y + r.rect.height,
            .text => |t| {
                const past = t.origin.y - bottom;
                if (past > worst) worst = past;
            },
            else => {},
        }
    }
    return worst;
}

test "a list longer than the transcript takes the rows it has and never one more" {
    // **The fault, one band down from the header clip.** A region that shared
    // its rows out by subtraction saturated at zero and then drew every row it
    // had been asked for. Those rows land under the band, where the next band's
    // own surface is painted over them, and what a person sees is a row of
    // glyphs cut through by a straight edge rather than a row that is not
    // there. See `Rows`.
    //
    // Mutation check: take the cut of `offered` out of `Ui.transcriptRows` and
    // leave the count, and the first expectation reports rows drawn well past
    // the transcript.
    const gpa = testing.allocator;
    // Six rows of transcript, and far more sessions than that.
    const h = try Headless.open(gpa);
    defer h.close();

    var offered: [30]Resumable = undefined;
    var names: [30][16]u8 = undefined;
    for (&offered, &names, 0..) |*one, *name, at| {
        one.* = .{
            .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            .words = std.fmt.bufPrint(name, "session {d}", .{at}) catch "session",
        };
    }
    h.screen.picker = &offered;
    h.screen.picked = 0;
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    // And the choice is on the screen wherever it is in the list, because a
    // list that cannot show what is chosen is a list nobody can answer.
    for ([_]usize{ 0, 12, 29 }) |at| {
        h.screen.picked = at;
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
        const shown = try screenText(h);
        // The row writes `\u{25b8}` and a cell backend paints `\u{25b6}`, which
        // is phantom's spelling of the same mark. See `markFor`.
        const wanted = try std.fmt.allocPrint(gpa, "{s} session {d}", .{ "\u{25b6}", at });
        defer gpa.free(wanted);
        try testing.expect(std.mem.indexOf(u8, shown, wanted) != null);
    }
}

test "a pane and an approval on a screen with almost no rows draw inside their bands" {
    // The same fault in the other two regions that share their rows out. A pane
    // keeps a title and a count, and an approval keeps the row that says how to
    // answer, so both of them wanted two rows on a band that has one.
    //
    // Mutation check: build the approval's first row before the keys row is
    // reserved and the three row screen below loses the row that says how to
    // answer; drop the row count check in `Rows.add` and the pane draws a row
    // under its own band.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]u16{ 3, 4, 5, 6 }) |rows| {
        const h = try Headless.openSized(gpa, .{
            .cols = 40,
            .rows = rows,
            .xpixel = 320,
            .ypixel = @as(u16, rows) * 16,
        });
        defer h.close();

        h.screen.openHelp();
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

        h.screen.pane = null;
        h.screen.showApproval(.{
            .request_id = 1,
            .action = "git.push",
            .summary = "push the branch",
            .reason = "the work is done",
            .chain = "main",
            .depth = 0,
            .detail = "one\ntwo\nthree\nfour\nfive\nsix",
            .left_ms = 30_000,
        });
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

        // **And the row that is kept is the one that says how to answer.** An
        // approval shows its own keys in its own region, and a user must never
        // have to remember, or press `?` under a deadline. So the keys row is
        // taken out of the room before anything else can use it, and a region
        // with one row is that row.
        try testing.expect(std.mem.indexOf(
            u8,
            try screenText(h),
            // What that row says depends on whether this display holds the
            // keyboard, and a display with no device names the command that
            // answers instead. Either way it is the row that must not drop.
            elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
        ) != null);

        // And in the view that fills the region with the agent's own bytes.
        h.screen.approval.?.view = .diff;
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
        try testing.expect(std.mem.indexOf(
            u8,
            try screenText(h),
            // What that row says depends on whether this display holds the
            // keyboard, and a display with no device names the command that
            // answers instead. Either way it is the row that must not drop.
            elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
        ) != null);
    }
}

test "the header of a proportional display keeps every layer name at a width a column count would have lost" {
    // **The visible half of the wrapping fault.** A column as wide as the
    // widest glyph turned a real ghostty into about half the columns it has,
    // and the header then shed every layer name to a bare tick: it read "chock
    // chock worktree" and six marks. That is exactly what is forbidden, because
    // a layer would then rest on a glyph and a colour alone.
    //
    // Mutation check: return the widest printable advance from `Measure.step`
    // in place of the mean and the names go, because the same display then
    // measures under `narrow_columns`.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A real ghostty, 158 cells of 9 by 22 pixels, drawn with the theme's own
    // face at its own size. That is the display the fault was measured on.
    const size: f32 = 24;
    const measure = faceMeasure(&font, size).measured();
    const room = Room{ .measure = measure, .width = 158.0 * 9.0 / (22.0 / 16.0) };

    var said: std.ArrayList(HeaderPiece) = .empty;
    try headerPieces(arena, .{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7-flash:A3B",
        .provider = "local",
        .layers = &every_layer_on,
    }, room, &said);

    var line: std.ArrayList(u8) = .empty;
    for (said.items) |one| try line.appendSlice(arena, one.text);

    try testing.expect(!room.isNarrow());
    for (every_layer_on) |one| {
        try testing.expect(std.mem.indexOf(u8, line.items, one.name) != null);
    }
    // And the whole row still measures inside the display it was built for.
    try testing.expect(room.holds(line.items));
}

test "a marker is pinned at the measure the row was cut to and not at the edge of the display" {
    // **The row that is drawn and the row that is only measured must answer
    // alike.** `spread` cuts the words to the transcript's measure and puts the
    // marker after them, and `Ui.pinnedRow` lays the same row out again with
    // the marker aligned right. Aligned inside the band, that marker sat at the
    // far edge of a wide display, tens of columns away from the words it names.
    //
    // Mutation check: drop the width from the `SizedBox` in `Ui.pinnedRow` and
    // the marker below lands at the right hand edge of the whole display.
    const gpa = testing.allocator;
    const wide: u16 = 200;
    const h = try Headless.openSized(gpa, .{
        .cols = wide,
        .rows = 10,
        .xpixel = wide * 8,
        .ypixel = 160,
    });
    defer h.close();

    // A fold, which is what carries a marker: reasoning the agent can be asked
    // to show.
    h.screen.observer().onPiece(.{ .reasoning = "a thought" });
    h.screen.observer().onPiece(.{ .text = "the answer" });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    const measure = h.screen.measure;
    const across = h.screen.transcriptRoom().width;
    try testing.expect(across < h.screen.screenRoom().width);

    var found = false;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        const said = switch (one) {
            .text => |t| t,
            else => continue,
        };
        if (std.mem.indexOf(u8, said.text, "show") == null) continue;
        found = true;
        // The marker ends at the measure, not at the edge of the display. The
        // display list is physical and the measure is logical, so the run is
        // divided back by the ratio the layout ran at.
        const ends = (said.origin.x + measure.widthOf(said.text)) / measure.dpr;
        try testing.expectApproxEqAbs(across, ends, 1);
    }
    try testing.expect(found);
}

test "a region takes the rows it was given and drops the rest" {
    // **The guard behind the three regions that share their rows out.** Each of
    // them works its own counts out and the counts are checked by tests of
    // their own, but a count is arithmetic and this is the thing that cannot be
    // got wrong: a region asked for one row more than it has drops that row.
    //
    // Mutation check: let `Rows.add` append whatever it is given and the third
    // row below is kept, which on a screen is a row drawn under the band and
    // painted over by the band beneath it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = phantom.Text{ .text = "row" };
    const one = text.widget();

    var two = Rows{ .left = 2 };
    two.add(arena, one);
    two.add(arena, one);
    two.add(arena, one);
    try testing.expectEqual(@as(usize, 2), two.items().len);
    try testing.expectEqual(@as(u16, 0), two.left);

    // A region with no rows draws nothing at all.
    var none = Rows{ .left = 0 };
    none.add(arena, one);
    try testing.expectEqual(@as(usize, 0), none.items().len);
}

test "what this file measures a row as is what phantom lays it out as" {
    // **The cut and the break have to agree.** Phantom decides where a row
    // breaks and this file decides where a row is cut, and each asks its own
    // copy of the same question per glyph, because phantom's copy wants an
    // allocator and a laid out run and `Room` has neither. A drift between them
    // is a row measured as fitting that does not, which is the whole fault this
    // work is about.
    //
    // Mutation check: leave the divide by the ratio out of `advanceOf` and the
    // HiDPI grid below disagrees by the ratio.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const words = "the quick brown fox, 255/255 passed. \u{3042}\u{3044}";
    // A real face at a real size, and a character grid at two ratios.
    const each = [_]Measure{
        faceMeasure(&font, 24),
        faceMeasure(&font, 24).measured(),
        .{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(9, 18) },
            .dpr = 18.0 / phantom.tui.term.logical_cell_h,
            .font = &font,
            .size = 24,
        },
        .{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(19, 37) },
            .dpr = 37.0 / phantom.tui.term.logical_cell_h,
            .font = &font,
            .size = 24,
        },
    };
    for (each) |measure| {
        var line = try phantom.text.layout.layoutLine(
            gpa,
            measure.font,
            words,
            measure.size,
            measure.logicalMetrics(),
        );
        defer line.deinit(gpa);
        try testing.expectApproxEqAbs(line.width, measure.widthOf(words), 0.001);
        // And the row height the band is built from is the run's own height.
        try testing.expectApproxEqAbs(line.height, measure.height(), 0.001);
    }
}

test "a display drawn with a real face keeps every row inside its band" {
    // **The character grid hides this whole class.** There a row is one cell
    // and `phantom.tui.term.logical_cell_h` is that same cell, so a band built
    // from the nominal number and a band built from the measured one are the
    // same band, and every other display test passes either way. A real face
    // measures 1.2 em, so the two differ by a fifth of a row and every row of
    // the screen drifts down until the last of them is under the band.
    //
    // Mutation check: size the band in `Ui.band` with
    // `phantom.tui.term.logical_cell_h` in place of `measure.height()` and the
    // rows below are drawn well past the band that holds them.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{
        .cols = 100,
        .rows = 30,
        .xpixel = 900,
        .ypixel = 660,
    });
    defer h.close();

    // The proportional metrics the pixel backend uses, on a session a test can
    // drive. `Measure` reads this on the next build, which is what a real
    // pixels run has from its first frame.
    h.screen.surface.terminal.owner.text_metrics = .proportional;

    var said: usize = 0;
    while (said < 40) : (said += 1) {
        h.screen.say(.agent, "a row of the agent's own words, long enough to wrap more than once\n");
    }
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());

    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    // And the rows really are the measured ones: a band of `rows` line boxes
    // holds `rows` runs and not the cell count the terminal reports.
    try testing.expect(h.screen.rows > 0);
    try testing.expect(h.screen.rows < 30);
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);

    // Every row was wrapped to the measure rather than cut off at it, so no row
    // ends in the middle of a word that the next row does not carry on.
    const room = h.screen.roomFor(.agent);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    for (h.screen.showRows(arena_state.allocator())) |one| {
        try testing.expect(room.holds(one.text));
    }
}

/// The mark phantom was asked to draw for `id`, or null when the frame drew
/// none of them.
fn drawnMark(h: *Headless, id: phantom.icon.Id) ?phantom.display_list.IconPrimitive {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .icon => |mark| if (mark.id == id) return mark,
            else => {},
        }
    }
    return null;
}

/// Whether any run of text this frame drew carries `point`.
fn drawsPoint(h: *Headless, point: u21) bool {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| for (t.glyphs) |glyph| {
                if (glyph.cp == point) return true;
            },
            else => {},
        }
    }
    return false;
}

/// A display drawn with a real face, which is what the pixel backend has.
///
/// **One frame before the caller says anything**, because `Measure` is read
/// during a build and `Ui.screenRoom` answers from what the last frame read. A
/// display asked for a proportional face and painted once still laid its first
/// frame out on the cell grid.
fn openProportional(gpa: std.mem.Allocator, columns: u16, rows: u16) !*Headless {
    const h = try openWide(gpa, columns, rows);
    errdefer h.close();
    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    // The face and not the cell, which is the whole reason to open one of
    // these: a run drawn at the theme's size is taller than a nominal cell.
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);
    return h;
}

test "every codepoint Chock draws as a mark is one the theme's own face has no glyph for" {
    // **The measurement the whole change rests on.** The two bundled faces are
    // display faces with no box drawing and no tick, so every one of these
    // resolved to glyph 0 and rasterised as a replacement box. Reading the
    // advance is how that is known without a rasteriser: glyph 0 has one
    // advance and every real glyph has its own.
    //
    // Mutation check: put `\u{b7}` or `\u{2026}` in `markFor` and the second
    // block below fails, because the face draws both of those correctly and a
    // mark would replace a glyph a person can already see.
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    const measure = Measure{ .metrics = .proportional, .dpr = 1, .font = &font, .size = 16 };

    // A private use codepoint no face assigns, which is glyph 0 by definition.
    const missing = measure.advanceOf('\u{e000}');
    try testing.expect(missing != measure.advanceOf('A'));

    for ([_]u21{
        '\u{2713}',
        '\u{2717}',
        '\u{2502}',
        '\u{2500}',
        '\u{25b8}',
        '\u{25be}',
        '\u{22ef}',
    }) |point| {
        try testing.expect(markFor(point) != null);
        try testing.expectEqual(missing, measure.advanceOf(point));
    }

    for ([_]u21{ '\u{b7}', '\u{2026}' }) |point| {
        try testing.expect(markFor(point) == null);
        try testing.expect(measure.advanceOf(point) != missing);
    }
}

/// A session that draws every mark `markFor` knows at once: a rail, a rule, a
/// tick, a cross, a fold that is shut, a fold that is open, and a call that is
/// still going.
///
/// **Two folds and not one**, because opening a fold turns its own marker over.
/// The reasoning block stays shut and carries `\u{25b8}`, the result is opened
/// and carries `\u{25be}`, so both chevrons are on the one screen.
fn everyMarkSession(h: *Headless) !void {
    h.screen.describe(.{ .layers = &.{
        .{ .name = "seccomp", .state = .on },
        .{ .name = "landlock", .state = .off },
    } });
    h.screen.say(.chock, "\u{2500}\u{2500} 3 rows above. The log keeps them.\n");
    // The words are what close the reasoning block and put its folded row on
    // the screen: a block still being written has no row yet.
    h.screen.observer().onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    h.screen.observer().onPiece(.{ .text = "The build file names a test step. I will run it.\n" });
    callAndAnswer(h, "255/255 passed\n", false, 18_200);

    // Down takes the newest row that opens, which is the result, and Space
    // opens it. Each key is read by the frame after the one it was pressed in.
    try focusTranscript(h);
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());

    // A call with no result, so its row keeps the mark that says it is going.
    h.screen.observer().onEvent(3, .{ .tool_call = .{
        .call_id = "c2",
        .tool = "read_file",
        .arguments = a_test_command,
    } });
    try testing.expect(h.screen.paint());
}

test "in pixels every mark is a drawn vector and the codepoint it stands for is gone" {
    // **PIXELS mode cannot be driven through tmux**, which carries no kitty
    // graphics, so this is where the pixel backend is checked. Every one of
    // these codepoints is glyph 0 in the theme's own face, so a run of text
    // holding one rests on phantom's fallback, and this is what says the
    // display asked for the mark itself and never left it to that.
    //
    // Mutation check: take any one line out of `markFor` and that mark's `icon`
    // primitive is gone while its codepoint comes back in a run of text, so
    // both halves of the pair below fail together.
    const gpa = testing.allocator;
    // **Rows enough that nothing scrolls off.** A proportional row is taller
    // than a cell, so a screen that holds this session on a character grid
    // drops its oldest rows here, and the rail goes with them.
    const h = try openProportional(gpa, 100, 32);
    defer h.close();

    try everyMarkSession(h);

    // Every one of the seven, drawn by phantom out of its own path.
    for ([_]phantom.icon.Id{
        .check,
        .cross,
        .rule_vertical,
        .rule_horizontal,
        .chevron_right,
        .chevron_down,
        .ellipsis,
    }) |id| {
        if (drawnMark(h, id) == null) return error.MarkNotDrawn;
    }

    // And not one of them still in a run of text, where the face would have
    // drawn a replacement box.
    for ([_]u21{
        '\u{2713}',
        '\u{2717}',
        '\u{2502}',
        '\u{2500}',
        '\u{25b8}',
        '\u{25be}',
        '\u{22ef}',
    }) |point| {
        try testing.expect(!drawsPoint(h, point));
    }
}

test "in cells the two chevrons change spelling and nothing else does" {
    // **The deliberate part of this, pinned where a change of it is a failure.**
    // A mark reaches a cell backend as `phantom.icon.cellMarkFor` spells it, and
    // phantom spells the two chevrons with the large triangles. So `\u{25b8}`
    // and `\u{25be}` are the only two codepoints the terminal capture lost, and
    // a capture taken with tmux against the two binaries showed exactly that
    // pair and no other difference.
    //
    // Mutation check: expect `\u{25b8}` back in the grid and the first loop
    // fails; take `'\u{22ef}'` out of `markFor` and nothing here moves, which is
    // why the pixels test above is the one that pins that line.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{
        .cols = 80,
        .rows = 20,
        .xpixel = 640,
        .ypixel = 320,
    });
    defer h.close();

    try everyMarkSession(h);
    const shown = try screenText(h);

    // The small triangles are gone from the grid, and the large ones are there
    // in their place.
    for ([_]u21{ '\u{25b8}', '\u{25be}' }) |point| {
        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) == null);
    }
    for ([_]u21{ '\u{25b6}', '\u{25bc}' }) |point| {
        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) != null);
    }

    // **And the mark of a running call is unmoved**, because phantom spells
    // `.ellipsis` with the very codepoint the row writes. This is the one of
    // the three that costs a terminal nothing.
    try testing.expect(std.mem.indexOf(u8, shown, "\u{22ef} read_file") != null);

    // **Where the whole of the change is, stated at the table.** Every mark
    // but the two chevrons reaches a cell backend as the very codepoint the row
    // wrote, so this change reached those two and stopped there.
    for ([_]u21{ '\u{2713}', '\u{2717}', '\u{2502}', '\u{2500}', '\u{22ef}' }) |point| {
        const mark = markFor(point) orelse return error.NoMarkForPoint;
        try testing.expectEqual(point, phantom.icon.cellMarkFor(mark.id).?.cp);

        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) != null);
    }
    for ([_]u21{ '\u{25b8}', '\u{25be}' }) |point| {
        const mark = markFor(point) orelse return error.NoMarkForPoint;
        try testing.expect(phantom.icon.cellMarkFor(mark.id).?.cp != point);
    }
}

test "a mark takes the room its own codepoint was measured to take" {
    // **This is what leaves every row where it was.** `wrapText`, `visibleLine`
    // and `spread` all step by `Measure.advanceOf`, so a mark drawn in any
    // other width moves the words beside it away from where they were
    // measured to go, and on a character grid it stops being one cell.
    //
    // Mutation check: size the box in `markBox` by `measure.height()` and the
    // drawn width is the row height rather than the advance, which fails the
    // first expectation and pushes the words after the rail out of place,
    // which fails the second.
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 12);
    defer h.close();

    h.screen.say(.chock, "under the rail\n");
    try testing.expect(h.screen.paint());

    const rail = drawnMark(h, .rule_vertical) orelse return error.NoRailDrawn;
    const measure = h.screen.measure;
    const advance = measure.advanceOf('\u{2502}') * measure.ratio();
    try testing.expectEqual(advance, rail.size.width);

    // The words of that row begin exactly one advance past the mark, which is
    // where the character would have left them.
    const words = drawnEdgeOf(h, " under the rail") orelse return error.NoWordsDrawn;
    try testing.expect(words > rail.origin.x + advance);
    try testing.expectEqual(rail.origin.x + advance, wordsStartOf(h, " under the rail").?);
}

/// Every mark of `id` the frame drew, in the order it drew them.
fn drawnMarks(
    gpa: std.mem.Allocator,
    h: *Headless,
    id: phantom.icon.Id,
) !std.ArrayList(phantom.display_list.IconPrimitive) {
    var found: std.ArrayList(phantom.display_list.IconPrimitive) = .empty;
    errdefer found.deinit(gpa);
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .icon => |mark| if (mark.id == id) try found.append(gpa, mark),
            else => {},
        }
    }
    return found;
}

test "the rail is one continuous line down the rows and the marks beside it stay square" {
    // **The fault this fixes.** A rule drawn square is as tall as it is wide,
    // about 16.75 of a 28.8 pixel row, so each row broke the line again and the
    // rail read as a dashed one. Only the pixel backend was ever affected: a
    // terminal paints `\u{2502}` from its own font, which is full height by
    // design.
    //
    // Mutation check: put the rail back to `.fit = .square`, or give its icon
    // back to `phantom.Align`, and the rail is one advance tall rather than one
    // row, which fails the height and opens a gap between every pair of rows.
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 12);
    defer h.close();

    h.screen.describe(.{ .layers = &.{
        .{ .name = "seccomp", .state = .on },
        .{ .name = "landlock", .state = .off },
    } });
    h.screen.say(.chock, "one row\ntwo rows\nthree rows\n");
    try testing.expect(h.screen.paint());

    const measure = h.screen.measure;
    const row = measure.height() * measure.ratio();
    const advance = measure.advanceOf('\u{2502}') * measure.ratio();
    // The row really is taller than the mark is wide, or the two shapes agree
    // and this test could not tell them apart.
    try testing.expect(row > advance);

    var rails = try drawnMarks(gpa, h, .rule_vertical);
    defer rails.deinit(gpa);
    try testing.expect(rails.items.len >= 3);
    for (rails.items) |one| try testing.expectEqual(row, one.size.height);

    // **What continuous means, measured.** Each rail ends exactly where the one
    // below it begins, in the same column, so the rows join into one line.
    for (rails.items[1..], rails.items[0 .. rails.items.len - 1]) |below, above| {
        try testing.expectEqual(above.origin.x, below.origin.x);
        try testing.expectEqual(above.origin.y + above.size.height, below.origin.y);
    }

    // **And the symbols did not stretch with it.** A tick pulled to the height
    // of a row is a distorted tick, so `.fill` on the pair that means a line
    // must not reach these.
    for ([_]phantom.icon.Id{ .check, .cross }) |id| {
        const one = drawnMark(h, id) orelse return error.NoSymbolDrawn;
        try testing.expectEqual(one.size.width, one.size.height);
        try testing.expect(one.size.height < row);
    }
}

/// Where the drawn run that spells `words` begins, and null when nothing on the
/// screen spells it. See `drawnEdgeOf`, which answers for the other end.
fn wordsStartOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                var spelled: [64]u8 = undefined;
                var at: usize = 0;
                for (t.glyphs) |glyph| {
                    if (at + 4 > spelled.len) break;
                    at += std.unicode.utf8Encode(glyph.cp, spelled[at..]) catch break;
                }
                if (!std.mem.eql(u8, spelled[0..at], words)) continue;
                return t.origin.x;
            },
            else => {},
        }
    }
    return null;
}

test "a header row that holds a mark is no wider than its own words" {
    // **The fault this found.** A horizontal `phantom.Flex` with a bounded main
    // axis reports the box it was offered and not what its children take, so
    // the first layer that carried a tick claimed the whole header and every
    // layer after it was drawn off the right hand edge.
    //
    // Mutation check: drop `.width` from the `SizedBox` in `marked` and the
    // last layer is drawn about a screen's width past the edge.
    //
    // **Wide enough that the header keeps its layer names.** Under
    // `narrow_columns` a layer that is on is shed to its glyph alone, and there
    // would be no word to look for. See `layerText`.
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 140, 12);
    defer h.close();
    try testing.expect(!h.screen.screenRoom().isNarrow());

    h.screen.describe(.{ .layers = &every_layer_on });
    try testing.expect(h.screen.paint());

    // The last layer of six, still on the screen and still inside it.
    const last = drawnEdgeOf(h, " landlock") orelse return error.NoLastLayerDrawn;
    try testing.expect(last <= screenEdge(h));
}

test "the name a reader hears is not the character a terminal paints" {
    // **Two fields for two readers, and neither stands in for the other.**
    // `phantom.Icon.label` is what a screen reader announces, and
    // `phantom.icon.cellMarkFor` is what a character terminal puts in the cell.
    // Passing one where the other belongs gives a terminal the word `ok` in a
    // cell, or a reader the name of a shape.
    //
    // Mutation check: give `.rule_vertical` a label in `markFor` and the rail
    // announces itself on every row Chock speaks on, which fails the third
    // expectation; take the name off `.ellipsis` and a running call says
    // nothing while the tick and the cross beside it both speak.
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 32);
    defer h.close();

    try everyMarkSession(h);

    const tick = drawnMark(h, .check) orelse return error.NoTickDrawn;
    try testing.expectEqualStrings("ok", tick.label.?);
    try testing.expectEqual(@as(u21, '\u{2713}'), phantom.icon.cellMarkFor(.check).?.cp);

    const rail = drawnMark(h, .rule_vertical) orelse return error.NoRailDrawn;
    try testing.expect(rail.label == null);
    try testing.expectEqual(@as(u21, '\u{2502}'), phantom.icon.cellMarkFor(.rule_vertical).?.cp);

    // **A call that is going says so**, because its mark is the third of the
    // three a call row carries and the other two are named.
    const going = drawnMark(h, .ellipsis) orelse return error.NoRunningMarkDrawn;
    try testing.expectEqualStrings("running", going.label orelse "");
    try testing.expectEqual(@as(u21, '\u{22ef}'), phantom.icon.cellMarkFor(.ellipsis).?.cp);

    // **And a chevron says nothing**, because the words that say what it means
    // are on the row beside it and they differ in each of its three places.
    for ([_]phantom.icon.Id{ .chevron_right, .chevron_down }) |id| {
        const one = drawnMark(h, id) orelse return error.NoChevronDrawn;
        try testing.expect(one.label == null);
    }
}

test "a session that ended leaves Chock's own row newest, with nothing drawn under it" {
    // **The shape a capture from the owner showed, measured where a terminal
    // cannot see it.** That capture had the model's first row drawn a second
    // time under the row saying the session ended, cut short and in the model's
    // colour. `transcriptRows` draws `pending` after `shown`, so an open row
    // left behind at the end of a turn is exactly that picture: put the words
    // back into `pending` by hand after the sequence below and the frame gains
    // one more row, under the Chock row, at the agent's indent and in the
    // agent's colour.
    //
    // **PIXELS mode and not a cell grid.** The two faces measure differently,
    // so the row count, the widths and where each row lands are not the numbers
    // a terminal has, and the marks are drawn rather than written as
    // codepoints. The geometry is `Attach.Window`'s own default, 960 by 640.
    //
    // Mutation check: force `open` to 1 in `transcriptRows` and the Chock row is
    // no longer the last row of the band, which fails the second expectation;
    // drop the `endLine` at the end of `sayFmt` and the row that says the
    // session ended is never closed, which fails the first.
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 120, 40);
    defer h.close();

    h.screen.describe(.{ .model = "glm4.7-flash", .provider = "z.ai" });
    h.screen.saidByUser("hello");
    const watching = h.screen.observer();
    watching.onPiece(.{ .reasoning = "the project is a Zig one, so the greeting names it" });
    // A word at a time, which is how the model's own answer arrives.
    const said = "Hi! I'm Chock, ready to help you.\n\nWhat would you like to work on?";
    var at: usize = 0;
    while (at < said.len) : (at += 7) {
        watching.onPiece(.{ .text = said[at..@min(at + 7, said.len)] });
    }
    watching.onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    watching.onEvent(2, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    // The field opens again for the next message, which is where the capture
    // was taken.
    h.screen.beginInput();
    try testing.expect(h.screen.paint());

    // Nothing is still being written, so no row is open to draw.
    try testing.expectEqual(@as(usize, 0), h.screen.pending.items.len);

    const step = h.screen.measure.height() * h.screen.measure.ratio();
    const parts = split(h.screen.rows, h.screen.approvalRows());
    const input_top = @as(f32, @floatFromInt(parts.header + parts.transcript)) * step;

    const ended = drawnTopOf(h, " session ended, finished") orelse
        return error.NoEndingDrawn;
    try testing.expectApproxEqAbs(input_top - step, ended, 0.01);

    // And the band under that row is empty: every other thing the frame drew is
    // above it, or is the input band's own.
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        const top = switch (one) {
            .text => |words| words.origin.y,
            .icon => |mark| mark.origin.y,
            else => continue,
        };
        try testing.expect(top <= ended or top >= input_top);
    }
}

/// How far down the frame drew the run reading `words`, or null when it drew
/// none. The twin of `drawnEdgeOf`, down instead of across.
fn drawnTopOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |said| if (std.mem.eql(u8, said.text, words)) return said.origin.y,
            else => {},
        }
    }
    return null;
}

test "the display reads a key and repaints while the session is waiting for something else" {
    // **The fault this fixes.** `draw` is the only place a key is read and the
    // screen repaints, and every one of its four callers is an event arriving.
    // Between two events nothing read the keyboard at all, so a person could not
    // scroll while a tool call ran and could not scroll at all while the harness
    // waited for the first token of a reply. See `Ui.pumpStep`.
    //
    // Mutation check: drop the `paint` from `pumpStep` and the scroll never
    // reaches the screen; drop the read and the arrow is never dispatched.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    // More rows than the screen holds, so there is something above to scroll to.
    for (0..8) |_| callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 1200);
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(u16, 0), h.screen.scroll_back);

    // No event arrives here at all: this is the wait itself.
    h.screen.surface.terminal.feed("\x1b[A");
    h.screen.pumpStep();
    h.screen.pumpStep();

    try testing.expect(h.screen.scroll_back != 0);
    // And the rows a person scrolled to are on the screen, which is the half a
    // read on its own would not have given them.
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "rows above") != null);
}

test "the pump gives the signal key back between two looks, so Ctrl-C stays the kernel's to deliver" {
    // **This is what keeps `src/interrupt.zig` owning Ctrl-C through a turn.**
    // Raw mode turns `ISIG` off, so a press arrives as `0x03` and only somebody
    // reading the device can act on it; a pump that held raw mode for the whole
    // of a wait would swallow every press that landed between two of its own
    // reads. So the device is raw for one look and is put back at the end of it.
    //
    // Mutation check: hold the keyboard across looks, by dropping the `defer
    // giveKeys` in `pumpStep`, and the last two expectations fail.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    try testing.expect(h.screen.keys.?.raw);

    h.screen.pumpStep();
    try testing.expect(!h.screen.keys.?.raw);
    // The person's own settings, signals and all, with only the echo taken out:
    // see `quietOf`.
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(!Settings.now().lflag.ECHO);

    // And the next look takes it again, so a key is still read: raw mode goes
    // on, and comes straight back off at the end of that look.
    h.screen.pumpStep();
    try testing.expectEqual(@as(usize, 3), Settings.only.count);
    try testing.expect(!Settings.only.written[1].lflag.ISIG);
    try testing.expect(Settings.only.written[2].lflag.ISIG);
    try testing.expect(!h.screen.keys.?.raw);
}

test "the pump takes no key while a question is open, because the question is already reading one" {
    // Two readers on one descriptor race for every byte. An approval and an ask
    // each hold the keyboard for as long as the question is up, through
    // `awaitAnswer` and `awaitText`, so the pump stands off.
    //
    // Mutation check: drop either guard at the top of `pumpStep` and the region
    // loses keys to the pump.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    try askIn(h, a_question);
    const held = Settings.only.count;
    h.screen.pumpStep();
    try testing.expectEqual(held, Settings.only.count);
    h.screen.clearApproval();

    holdsTerminal(h);
    h.screen.showQuestion(.{ .text = "which database?" });
    const open = Settings.only.count;
    h.screen.pumpStep();
    try testing.expectEqual(open, Settings.only.count);
    h.screen.clearQuestion();
}

test "a Ctrl-C read by the pump puts the device back first, and then raises the signal" {
    // The same property `awaitAnswer` keeps, and it has to hold here too: a
    // press that lands inside a look arrives as `0x03` with no signal sent, so
    // the pump raises it itself, and it puts the device back first because a
    // second press ends the process where it stands.
    //
    // Mutation check: raise before `giveKeys` and the second expectation fails,
    // which is a shell left in raw mode.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    Raises.only = .{ .screen = h.screen };
    h.screen.raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    holdsTerminal(h);
    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.screen.keys.?.device.in.close(io);

    h.screen.pumpStep();
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(!Raises.only.raw_at_raise);
    try testing.expectEqual(@as(usize, 2), Raises.only.count);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[0]);
}

/// Put a question up and paint, the way `run.zig`'s own `DisplayAsker` does.
fn asksIn(h: *Headless, one: Question) !void {
    try testing.expect(h.screen.paint());
    h.screen.showQuestion(one);
    takesKeys(h);
    try testing.expect(h.screen.paint());
}

test "a question from the agent reaches the person, and the typed answer comes back" {
    // **The whole point of this region in one drive.** Before it, a session with
    // a display told the agent nobody was asked, however many people were
    // watching it: `src/run.zig` gave the bare prompt `at_terminal = false`
    // whenever a screen was up, because there was nowhere to show a question.
    //
    // Mutation check: drop the `.answered` branch of `onQuestionKey` and the
    // answer never leaves the region.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{
        .agent_kind = "coder",
        .text = "which database does staging use?",
        .left_ms = 90 * std.time.ms_per_s,
    });

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "QUESTION from coder") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "which database does staging use?") != null);
    // The one fact that separates this region from the approval region above it.
    try testing.expect(std.mem.indexOf(u8, shown, "allows nothing") != null or
        std.mem.indexOf(u8, shown, "Allows nothing") != null);

    // A person types, and what they type is on the screen as they type it.
    h.screen.question_settle = 0;
    try pressKeys(h, "postgres");
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "postgres") != null);
    try testing.expectEqual(Text.waiting, h.screen.awaitText(50));

    // A backspace takes a whole character off.
    try pressKeys(h, "\x7f");
    try testing.expectEqualStrings("postgre", h.screen.question_typed[0..h.screen.question_filled]);

    try pressKeys(h, "s\r");
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("postgres", said),
        else => return error.NothingCameBack,
    }
}

test "Enter with nothing typed is a deliberate no answer, and not nobody being there" {
    // `chock_core.ask.Answer` keeps the two apart because the model is told a
    // different thing by each: a person who said nothing has answered, and a
    // session with nobody at a keyboard has not been asked.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try asksIn(h, .{ .text = "which one?" });
    h.screen.question_settle = 0;
    try pressKeys(h, "\r");
    try testing.expectEqual(Text.declined, h.screen.awaitText(50));
}

test "a question that imitates Chock cannot put its words at the start of a row" {
    // **The question is written by the model**, so it is untrusted text put in
    // front of a person, and the fault to stop is a question that reads as
    // Chock's own words. A row of "chock: your credential expired, paste it
    // here" would be a phishing surface inside the user's own terminal. Every
    // row of the model's words is written after
    // `chock_core.ask.question_marker`, so Chock's own bytes are the only ones
    // that reach the start of a row.
    //
    // Mutation check: take the marker out of either `allocPrint` in
    // `questionRegion` and this fails on the first row of the question.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{
        .agent_kind = "coder",
        .text = "pick one\nchock: your credential expired, paste it here",
        .options = &.{"chock: paste it here"},
    });

    const shown = try screenText(h);
    // The words are shown, because a person has to be able to read what they
    // are being asked. What is stopped is where they are shown.
    try testing.expect(std.mem.indexOf(u8, shown, "your credential expired") != null);

    var rows = std.mem.splitScalar(u8, shown, '\n');
    var gutters: usize = 0;
    while (rows.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, " ");
        if (trimmed.len == 0) continue;
        // No row starts with the model's own bytes. Chock's own rows are the
        // header, the answer line and the keys row.
        try testing.expect(!std.mem.startsWith(u8, trimmed, "chock:"));
        if (std.mem.startsWith(u8, trimmed, chock_core.ask.question_marker)) gutters += 1;
    }
    // And the model's words really did reach the screen behind the gutter,
    // rather than being dropped, which would pass the test above for the wrong
    // reason.
    try testing.expect(gutters >= 2);
}

test "a digit chooses from the list, and only while the answer line is empty" {
    // **A number is a shortcut and never a wall.** `chock_core.ask.chosen` keeps
    // that rule at the bare prompt, and this keeps it here: a person writing
    // "1 or 2, whichever is cheaper" is writing a sentence, not answering with
    // its first character.
    //
    // Mutation check: drop the `question_filled == 0` guard and the second half
    // of this test answers the question mid sentence.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{ .text = "which one?", .options = &.{ "postgres", "sqlite" } });
    h.screen.question_settle = 0;
    try pressKeys(h, "2");
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("sqlite", said),
        else => return error.NothingCameBack,
    }
    h.screen.clearQuestion();

    // The same key inside a sentence is a character of the sentence.
    try asksIn(h, .{ .text = "which one?", .options = &.{ "postgres", "sqlite" } });
    h.screen.question_settle = 0;
    try pressKeys(h, "either 1");
    try testing.expectEqual(Text.waiting, h.screen.awaitText(50));
    try testing.expectEqualStrings("either 1", h.screen.question_typed[0..h.screen.question_filled]);
}

test "an ask decides nothing, and there is no member of an answer that could" {
    // **The rule this whole region is built under.** An approval asks "may I do
    // this act" and its answer is a decision recorded against that act; an ask
    // wants a fact a person holds, and answering one permits nothing. The two
    // regions look alike and share the rows `split` gives the raised panel, and
    // that is the whole of what they share. See `Question`, and
    // `lib/chock-core/ask.zig`'s own top comment.
    inline for (@typeInfo(Text).@"union".fields) |field| {
        const ok = field.type == void or field.type == []const u8;
        if (!ok) @compileError(
            "Text gained the member \"" ++ field.name ++ "\", which is neither a plain case nor " ++
                "the person's own words. An ask grants nothing, and a member that carried a " ++
                "decision would be the route by which one travelled",
        );
    }
    inline for (@typeInfo(Question).@"struct".fields) |field| {
        const ok = field.type == []const u8 or field.type == []const []const u8 or field.type == i64;
        if (!ok) @compileError(
            "Question gained the member \"" ++ field.name ++ "\", which is neither text nor the " ++
                "deadline. An ask names no act, and a member that named one would make this an " ++
                "approval by another name",
        );
    }

    // And answering one leaves the approval region's own answer untouched, so
    // no answer here can be read as a decision by the code that reads those.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try asksIn(h, .{ .text = "which one?" });
    h.screen.question_settle = 0;
    try pressKeys(h, "y\r");
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
    try testing.expect(h.screen.approval == null);
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("y", said),
        else => return error.NothingCameBack,
    }
}

test "the raised panel is an approval or a question and never both at once" {
    // They share the rows and nothing else: see `panelRows`.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expectEqual(@as(u16, 0), h.screen.panelRows());

    h.screen.showQuestion(.{ .text = "which one?" });
    try testing.expect(h.screen.panelRows() != 0);
    try testing.expectEqual(h.screen.questionRows(), h.screen.panelRows());

    // An approval takes the rows while it is open, because it is the one with an
    // act behind it.
    h.screen.showApproval(a_question);
    try testing.expectEqual(h.screen.approvalRows(), h.screen.panelRows());

    h.screen.clearApproval();
    h.screen.clearQuestion();
    try testing.expectEqual(@as(u16, 0), h.screen.panelRows());
}

test "an ask_user row shows the question and not the JSON it arrived as" {
    // `argumentText` has no tool name to go on and an `ask_user` call is two
    // members with no key it knows, so the row held
    // `{"question":"...","options":[...]}` where the question should have been.
    //
    // Mutation check: send an `ask_user` call through `argumentText` instead and
    // the first expectation finds the braces.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings(
        "which database?",
        try askArgumentText(arena, "{\"question\":\"which database?\"}"),
    );
    try testing.expectEqualStrings(
        "which database?  (2 to choose from)",
        try askArgumentText(
            arena,
            "{\"question\":\"which database?\",\"options\":[\"a\",\"b\"]}",
        ),
    );
    // A question of several lines gives the row its first line, because a row is
    // one line. The whole of it is in the region and in the log.
    try testing.expectEqualStrings(
        "pick one",
        try askArgumentText(arena, "{\"question\":\"pick one\\nor say why not\"}"),
    );
    // Nothing is invented when the shape is not known.
    try testing.expectEqualStrings("not json", try askArgumentText(arena, "not json"));
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", try askArgumentText(arena, "{\"a\":1,\"b\":2}"));
}

test "a backspace takes a whole character and never half of one" {
    // Half a character is text phantom cannot measure and a provider answers 400
    // to: see `chock_core.ask.cleanAnswer`, which removes the same class of
    // fault from the other end.
    try testing.expectEqual(@as(usize, 0), backOne(""));
    try testing.expectEqual(@as(usize, 2), backOne("abc"));
    // Three bytes, one character.
    try testing.expectEqual(@as(usize, 0), backOne("\u{4e2d}"));
    try testing.expectEqual(@as(usize, 1), backOne("a\u{4e2d}"));
}

test "a question grows with what it holds and stops at half the screen" {
    // The transcript is given up first, and the open approval views already
    // stop at half. A question longer than that is read in the transcript,
    // where the `tool.call` row also holds it.
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 24, .xpixel = 640, .ypixel = 384 });
    defer h.close();
    try testing.expect(h.screen.paint());

    h.screen.showQuestion(.{ .text = "one line" });
    const small = h.screen.questionRows();
    try testing.expect(small >= 4);

    h.screen.showQuestion(.{ .text = "a\nb\nc\nd\ne", .options = &.{ "1", "2", "3" } });
    try testing.expect(h.screen.questionRows() > small);

    var long: [80]u8 = @splat('\n');
    h.screen.showQuestion(.{ .text = &long });
    try testing.expect(h.screen.questionRows() <= h.screen.rows / 2);
    h.screen.clearQuestion();
}

test "a Ctrl-C says in the transcript what it did, because a frame takes the handler's own line off" {
    // **The handler writes one raw line past whatever is drawing**, and
    // `tty.noteScroll` then asks the display to paint every cell again, which is
    // what puts the screen back and what takes that line off it. While the
    // display was frozen between two events the line stayed up until the next
    // one; a display that repaints while it waits takes it off at once. So a
    // person who pressed once would have had nothing telling them that the work
    // carries on and that a second press ends it now.
    //
    // Mutation check: drop the `noteStopping` call from `pumpStep` and the
    // second expectation fails; drop the `said_stopping` guard and the row is
    // written ten times a second.
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    h.screen.pumpStep();
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "next safe point") == null);

    interrupt.requestStop();
    h.screen.pumpStep();
    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "next safe point") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "again to stop now") != null);

    // Once, and not once per look.
    const rows = h.screen.lines.items.len;
    h.screen.pumpStep();
    h.screen.pumpStep();
    try testing.expectEqual(rows, h.screen.lines.items.len);
}
