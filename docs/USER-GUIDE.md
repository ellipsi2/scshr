# scshr — see and control your Mac from a Windows PC

scshr shows your Mac's screen on a Windows PC, lets you use the Mac with this PC's mouse and
keyboard, and plays the Mac's sound here. It uses Apple's built-in Screen Sharing (the same
high-quality mode the Screen Sharing app on another Mac uses), and it protects the connection with a
private link between exactly this PC and that Mac.

You do **not** need to sit at the Mac. Everything is set up from this PC.

## What you need

On the Mac (one time, at the Mac or by asking whoever has access to it):

1. An **administrator** account on the Mac (user name + password).
2. **Remote Login** turned on: *System Settings › General › Sharing › Remote Login*.
   (Most people who already reach their Mac "over SSH" have this on.)
3. A Mac with Apple silicon (M1 or newer) running macOS 14 Sonoma or newer.
   Older Macs or macOS versions can connect but not in the high-quality mode.

On this PC:

* Windows 10 or 11 (64-bit), a graphics card from the last few years.
* The scshr folder (unzip it anywhere, for example your Desktop).

If the Mac is at home and you are somewhere else, the Mac's router must send **UDP port 51820** to
the Mac (usually called "port forwarding" in the router's settings). Setup tells you if this is
needed. On the same network (same house or office Wi-Fi) nothing else is required.

## First time: set up

1. Double-click **scshr.exe**. Windows asks for permission to make changes (scshr installs a small
   network service for the private link). Click **Yes**.
2. Fill in:
   * **Mac address** — the name or IP you use to reach the Mac (for example `my-mac.local`,
     `192.168.1.20`, or `home.example.net`).
   * **Mac user name** and **password** of an administrator account on the Mac.
   * If Remote Login on the Mac uses a port other than 22, tick **Advanced** and enter it in
     **SSH port**. (Writing `my-mac.local:2222` in the address box works too.)
3. Click **Set up** and wait. scshr connects to the Mac, installs its helper there, creates the
   private link on both sides, turns on Screen Sharing on the Mac, and tests everything.
   The password is used once and is not saved.
4. When you see **Your Mac is ready to use**, click **Open**.

If setup reports a problem, the message tells you what to do. The most common ones:

| Message | What to do |
|---|---|
| Could not reach the Mac | Check the address, that the Mac is on, and that Remote Login is on. |
| The Mac rejected the user name or password | Re-type them. The account must be an administrator. |
| This PC cannot reach the Mac's tunnel port | Forward UDP port 51820 on the Mac's router to the Mac, then **Set up again**. |
| Screen Sharing is off | Turn it on: *System Settings › General › Sharing › Screen Sharing*. |
| The Mac's identity has changed | The Mac was reinstalled or something is impersonating it. If you reinstalled the Mac, choose **Remove** and set up again. |
| Setup finished with a warning | The connection is set up; open the main window and click **Check connection** to see what is still missing. |

## Every day: connect

1. Open **scshr.exe**, click **Yes** on the permission prompt.
2. The window shows the Mac's name and whether it is reachable (**Ready**).
3. Type the Mac account's user name and password (this is the account you log in with on the Mac;
   tick **Remember password** if you like) and click **Connect**.
4. The Mac's screen appears in a window. Resize the window and the Mac's screen follows.

If somebody is sitting at the Mac, you normally get **your own separate session**: you sign in with your
account, they keep their screen, and neither of you disturbs the other (the Mac needs macOS 14 or newer,
and your account must not already be signed in at the Mac). If you would rather see and control the
same screen as the person at the Mac, choose **Options…** and pick **Share their screen**; they then
have to click **Allow** on the Mac.

While connected:

* Your mouse and keyboard act on the Mac. The Windows key works as the Mac's ⌘ (Command) key,
  Alt as ⌥ (Option), Ctrl as ⌃ (Control).
* Sound from *your* session on the Mac plays on this PC, through whatever output device Windows uses.
  The person sitting at the Mac keeps their own sound on the Mac's speakers, and the Mac's sound
  settings stay theirs. The first time, the Mac asks (inside your session) whether *scshr-tunnel* may
  record this computer's audio — click **Allow**; until then you hear nothing.
* Text you copy on one side can be pasted on the other.
* Close the window to disconnect. If the connection drops, scshr offers to reconnect.

## Removing scshr

In the scshr window choose **Remove**. It removes the private link from this PC and, if you give the
Mac's administrator password, from the Mac as well. Then delete the scshr folder. Nothing else on
either machine is changed.

## Questions

**Is it safe?** The link between the PC and the Mac is encrypted end to end, only this PC can use it,
and while it is installed the Mac's Screen Sharing is reachable only through that link — not from the
rest of the network or the Internet. That also means other computers, iPads or phones that used to open
the Mac's screen over the network cannot do so while scshr is set up; choose **Remove** to give that back.

**Setup stopped half-way.** scshr puts the Mac back the way it was. If it reports that it could not,
run this on the Mac (or over SSH) to undo everything scshr did there:

```
sudo /usr/local/libexec/scshr-macos-tunnel.sh uninstall
```

**The Mac has its firewall turned on.** Setup registers its helper with the Mac's firewall. If the
connection test still fails, open *System Settings › Network › Firewall › Options* on the Mac and make
sure `scshr-tunnel` is allowed.

**Do I need to keep anything running on the Mac?** No. The helper starts by itself when the Mac
boots.

**Can two PCs share one Mac?** Not at the same time. Each PC needs its own setup, and setting up a
second PC replaces the first.

**Can I use the Mac while someone else is using it?** Yes. With the default *own separate session*
option you sign in with your account and work in your own session; the person at the Mac keeps their
screen, mouse and keyboard. Your account must be different from the one already signed in at the Mac.

**I hear nothing (or the Mac's speakers went quiet).** Sound from your session needs the Mac to have
been set up with this version of scshr — click **Set up** again if it was set up with an older one — and
needs macOS 14.2 or newer. If the Mac asked whether *scshr-tunnel* may record audio and you clicked
**Don't Allow**, turn it on in *System Settings › Privacy & Security › Screen & System Audio Recording*
on the Mac. The Mac's own speakers are never touched by scshr's default setting; if they went quiet, the
older whole-Mac sound mode is in use (`--audio-source host` on the command line).

**Something else went wrong.** In the scshr window click **Check connection** and read the message.
For deeper troubleshooting see `README.md` (technical) — the command line tools `scshr check` and
`scshr status` print details.
