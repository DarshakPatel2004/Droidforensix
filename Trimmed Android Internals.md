# Trimmed Android Internals

---

**Page 1**

I: The Evolution of Android's Architecture

Though Android is built on Linux and relies heavily on much of its infrastructure - most
notably the kernel - Android has become an operating system in a class by itself. Unlike OS X
and iOS, which share the majority of their code base (with the exception of the UI and several
frameworks), Android introduces a vast collection of frameworks, as well as a runtime to support
them (Dalvik). Indeed, most of the user-facing features and enhancements in between versions
have to do with additional frameworks and APIs being added, with only a relatively small portion
of them at the system level.

This Chapter explores the evolution of Android, and examines its architecture. Beginning
with the Android version history, from Cupcake (1.5) to Lollipop (5.1.1), and beyond, we cover
system-related features and enhancements in each. We then turn to examine the Android
architecture, comparing and contrasting with that of Linux. Each layer is described in detail,
laying the foundations for the even deeper exploration carried out in the next chapters (and
next volume) of this work. Finally, we consider the multitude of Android derivatives, as well as
future enhancements which may be expected in the next versions of this rapidly evolving OS.

---

**Page 2**

Android Internals::A Confectioner's Cookbook (Volume 1)

Android version history

Over its seven short years, Android has already undergone no less than a dozen versions.
When one considers the API versions (which map the internal set of APIs to the catchier
condiment type), this number increases to 22. Enumerating the many framework features
introduced in each version would be tedious and likely miss out on a few, so this section instead
aims to provide a more technical look, focusing on those API differences at the system (rather
than framework) level, as well as other noteworthy observations. Those seeking more
information about changes are suggested to read the comprehensive Wikipedia Entry’, or check
the Android documentation for the respective versions.

Table 1-1 shows the Android version history, and maps the official release version to that
of the API and the kernel. Note that the kernel versions don't necessarily match in all devices,
as some vendors compile their own kernel, or backport newer kernels.

Table 1-1: Android Versions, to date

Date Code Name Release API Kernel
Late 2015] M (final name unknown) 5.2 (Likely) | 22MRC

3/2015 . 5.1-5.1.1 22 3.4(armv7)/3.10(arm64)

Lollipop

11/2014 5.0-5.0.2 21

10/2013 KitKat 4.4-4.4.4 19 (20)

07/2013 JellyBean (MR2) 4.3 18 3.4
11/2012 JellyBean (MR1) 4.2-4.2.2 17

07/2012 JellyBean 4.1-4.1.1 16 3.0.31
12/2011 }Ice Cream Sandwich (MR1)]| 4.0.3-4.0.4 15

10/2011 Ice Cream Sandwich 4.0-4.0.2 14 3.0.1
07/2011 Honeycomb (MR2) 3.2-3.2.6 13

05/2011 Honeycomb (MR1) 3.1 12 2.6.36
02/2011 Honeycomb 3.0 11

02/2011 Gingerbread (MR1) 2.3.3-2.3.7 10 56.35
12/2010 Gingerbread 2.3-2.3.2 9

05/2010 Froyo 2.2-2.2.3 8 2.6.32
10/2009 Eclair 2.0-2.01, 2.1 5-7 2.6.29
09/2009 Donut 1.6 4 2.6.29

Actual usage (and probably some behavioral) data is compiled by Google, and is made
available through the Dashboards on the Android Developer Website’. Since there are virtually
no devices remaining with versions older than Froyo, this work does not make any attempt to
discuss them.

Froyo

FroYo (Frozen Yogurt) was the first version of Android to support application
installation on external media (i.e. SDCards). It additionally introduced the notion
of Android Secure Containers (ASEC), in order to provide security for files on
external media, which by its nature is usually FAT formatted volumes (The ASEC
mechanism is discussed in Chapter 2). Another useful feature introduced in this
version was USB tethering (connecting the device and using its Internet connection,
as discussed in Volume II). Lastly, Froyo brought significant speed improvements to
Dalvik, with the introduction of Just-In-Time (JIT) compilation by a dedicated thread.

---

**Page 3**

Chapter I: Introduction

Gingerbread

Gingerbread was the first version of Android to gain widespread adoption, and
with good reason: It introduced significant enhancements to the system. At the Dalvik
layer, concurrent garbage collection was introduced, which improved application zg
response time by running GC in parallel, rather than pausing the application during the
process. Likewise, the JIT mechanism improved on Froyo's. The sensor APIs
underwent a complete revamp, extending the sensor HAL to support more sensor
types, and making them more accessible to native code. Support for native code was bolstered in
other areas as well, providing native access to audio, graphics, storage and even the activity
manager. Gingerbread was also first to introduce support for Near-Field-Communications (NFC),
though it was only till later (with ICS) that NFC was to be adopted into ubiquity by Android vendors.

Another noteworthy addition is support for OBB - opaque binary blobs (referred to as "APK
expansion files") as a workaround to the size limitation of application package sizes, and to
provide optional encryption. OBB files are discussed in Chapter 2. Last, but not least,
Gingerbread adopted Ext4 in place of YAFFS as the default filesystem.

All these improvements aside, Gingerbread is actually most notorious for being the most
insecure version of Android to date. Apart from glitches with the stock SMS app (which
routed messages to the wrong recipients), it was riddled with quite a few vulnerabilities
which led to an explosion in rootkit-grade malware.

Honeycomb

Honeycomb brought Android to tablets. In fact, it was a "tablet-only"
release, in that the source tree was never fully released nor meant to be used
for phones (though some vendors still tried to use it nonetheless). The main
change was the introduction of fragments, which - like Windows’ Multiple
Document Interface (MDI) allow several client areas to coexist simultaneously,
rather than the single layout architecture which was previously used.

Honeycomb also offered significant improvements in graphics - introducing
hardware accelerated OpenGL rendering for 2D, and introduced Renderscript, which is
Android's own GL-like language.

Another feature of importance was the advent of storage encryption. Honeycomb was the
first version of Android to offer low level encryption of the user data partition, bringing it in line
with iOS 4, which introduced it as well. The disk encryption in Android is carried out by the
Linux device mapper, and can be thought of as the next step, following the Android Secure
Storage which was introduced in Froyo.

More important than the user space features was the introduction of multi-core support
into Android. Primarily, this involved a recompilation of the Linux kernel to support SMP (as
can be seen with the BusyBox uname tool, or /proc/version). Tablets were the first devices

to utilize multi-core architectures, which have since proliferated to all but the cheapest
devices. The Android Documentation® details the changes required for code to be SMP safe -
most of these are primarily in native code, though some aspects apply to Java as well.

Honeycomb was the only version of Android whose source code was not made open (aside
from select portions). This made some vendors wary, and brought to mind the fact that even
though Android is free, Google still controls the system, and its licensing may change at any
point in the future, if Google so sees fit.

---

**Page 4**

Android Internals::A Confectioner's Cookbook (Volume 1)

Ice Cream Sandwich

Ice Cream Sandwich (ICS) brought many changes to Android, as can
be expected from a 4.0 release. Aside from the myriad UI enhancements,
those changes which were noticeable to users included significant
connectivity enhancements - The Android VPN Framework, WiFi Direct
and Android Beam.

ICS adds another API often overlooked by developers - the onTrimMemory () callback,
which is called at times of memory pressure. According to the integer code specified, an
application should release as much memory as possible. Note, however, that this API is advisory
- applications can just choose to ignore the callback (which all too many, in fact, do).

JellyBean

on the same device. This feature, more useful on tablets than phones (and formally
only enabled on the former), allows several users to operate the device. Though only
one user can be actively logged on, each user has a different UI, with separate
widgets and applications and - most importantly - isolation of application data. We
discuss the implementation of this feature in detail in Chapter 8.

JellyBean's most prominent user-facing feature is in its support for multiple users | :

In addition to this, and alongside the slew of UI features, JellyBean also provided
application encryption and forward locking, building on Froyo's ASEC containers. One of the
main drawbacks of Android's open nature at the time was that it was trivial to pirate apps by
moving them between devices via the SDCard. ASEC provides a secure container for data,
which can be encrypted by the application, and made readable only by the application's uid
(but still fails miserably on rooted devices). This will, as mentioned, be covered in Chapter 2.

JellyBean went through three API versions, which introduced many changes, both over and
under the hood. API 17 also brought SELinux to Android for the first time (as detailed in
Chapter 8), and sealed a gaping USB debugging hole by forcing authentication over ADB.
Notable changes in API 18 were support for OpenGL ES 3.0, Bluetooth Audio-Video Remote
Control Profile (AVRCP) 1.3 and Bluetooth Low Energy (LE) support, as well as the App Ops
service (whose UI was later removed in 4.4.1), which allows tweaking application permissions.

KitKat

Version 4.4 of Android was codenamed "KitKat" (and was actually launched in
partnership with Hershey's). It represents a genuine attempt by Google to combat
the fragmentation of the Android universe: Though JellyBean is the single most
popular version, a large percentage of devices still use old versions - notably
GingerBread, which are not only obsolete, but hamper apps from running due to
their old API versions. Additionally, middle and high-end market become saturated,
and in the entry-level category Android faces competition from FireFox OS and
others.

KitKat's "pet project" was "svelte", an initiative to enable a smooth experience on virtually
any device, including low-end devices, with 512MB of RAM. Part of the rationale behind it is that
a smoother OS with less resource requirements would enable all vendors - even those with
entry level devices - to offer the latest OS version, thereby ending fragmentation. Doing so
involved many under-the-hood changes, such as rewriting framework code to use less memory,
and starting services in a serial manner (to reduce memory pressure). A new API was added to
detect low RAM devices (ActivityManager.isLowRamDevice(), which returns the value of the

ro.config.low_ram property). Using this API, developers can detect the amount of
RAM available, and plan resources accordingly. KitKat also added the procstats service to
give developers as much information as possible on their application's footprint.

---

**Page 5**

Chapter I: Introduction

For those devices which do have RAM, KitKat utilizes a new feature of the Linux Kernel,
called ZRAM. This feature is in fact newer than KitKat itself, having only been officially stabilized
and merged in version 3.14 (KitKat uses 3.4), but Google was an early adopter in both
ChromeOS and Android. The features enables swapping to RAM, and thus overcomes one of the
major limitations of mobile devices - the lack of swap on flash devices. While swapping to RAM
might sound somewhat counterproductive, it is in fact a dramatic improvement, as the swapped
pages are compressed (thus saving overall RAM usage) and quite fast to retrieve. Devices which
use compressed RAM will have a special block device (e.g. /dev/block/zram0O), indicated by
the /proc/swaps file.

Compressed memory also made its debut in iOS version 7.0, a few months before KitKat
was announced. Several other interesting features in KitkKat may have borrowed from iOS 7.0

include a step counter (software-defined sensor, as an answer to Apple's M7), as well as
timer coalescing and sensor batching. The latter two are a significant improvement that

helps maximize battery life. To do so, Android actually reduces the granularity of timers and
updates from sensors, making them more coarse, but also more likely to coincide. This can
greatly improve battery time - both directly (longer periods of CPU idle time), and indirectly
(reducing the overall number of wakeups, which are costly both in power and performance).

Other notable features in Kitkat include Bluetooth MAP support, Infrared Blaster
(ConsumerlIr) APIs, A new printing framework, and NFC host card emulation. Probably the most
far reaching change, however, was unannounced and kept under the scenes: introducing the
Android RunTime (ART), as an optional replacement to Dalvik.

At the time of writing, Kitkat has undergone four minor revisions, and its most recent
version is 4.4.4. Those revisions are mostly bug fixes and camera enhancements, and do not
change the API version, though internal APIs have been modified. KitkKat remains the most
common Android version, installed on 40% of devices (as of late April 2015).

Lollipop

The latest version of Android (at the time of writing) is Android Lollipop. The most
obvious user-facing change in this version is the introduction of "Material Design", a
flat interface which aims to provide realistic lighting and motion effects, and print-
based design which is strangely reminiscent of iOS 7's overhaul. Another emphasis in
this release is on notifications, support for which has been greatly expanded. |

Under the hood are far more significant changes: First and foremost is the adoption of
the Android Runtime (ART), which brings performance improvements by compiling Dalvik
code to native code Ahead Of Time (AOT), rather than Just In Time (JIT). Aside from
performance, ART also allows Android apps to exploit the benefits of 64-bit architecture, as
discussed in depth in Volume II. The graphics stack has been updated with support for
OpenGLES 3.1, and the audio frameworks have been upgraded, particularly for better audio
input handling. Likewise, camera APIs have been revamped. Sensor support (via the
Hardware Abstraction Layer) has been upgraded, with support for more complicated
gestures, and even a heart rate monitor. The "pet-project" of this release is "Project Volta",
which aims to both improve battery life (through the new job scheduling API) and provide
better power monitoring tools (notably, thebatterystats service). Lollipop also serves as
the foundation for the new "Android TV".

---

**Page 6**

Android Internals::A Confectioner's Cookbook (Volume 1)

Lollipop's release was quite lengthy and somewhat painful - It took Google about six
months from announcement (6/2014) to official launch (11/2014), and even at the time of
writing, it is supported mainly on the Google Nexi, with a penetration rate of about 10%

(and that, too, for versions before 5.1). Major bugs (ironically, relating to power management

and performance) have been discovered in the earlier releases, and - much to the chagrin of
vendors who are still playing catch up - pushed Google to update Lollipop (as of 03/2015) to
5.1, with API level 22, and numerous bugfixes. 5.1 adds myriad UI tweaks, and - more
importantly - notable features such as HD-Voice calling, Dual-SIM support, and "Device
Protection" (the much needed "kill switch" to lock stolen devices remotely).

Android M (final name as yet is unknown) is Google's latest version of Android - It was
announced in Google I/O on 5/28/2015. Having learnt from the mistakes made with L, Google
has committed to a strict timeline consisting of three developer releases, each a month apart,
with a final release date by the end of Q3 2015. Google provided both Emulator and factory
images (for the Google Nexi), including - for the first time - images for ARM64, which the
QEMU emulator in the Android SDK now supports. Sources are also available through the
Android GIT repository.

From a feature perspective, M seems more of an evolutionary update, than a revolutionary
one. While it adds several noteworthy features, these are mostly in response to iOS, and
include support for payments, built-in fingerprint authentication (which was introduced in
Lollipop, but is now made available for use by apps), and floating toolbars for text selection.

An important improvement comes int the form of revamping the App permission model,
which finally moves the permission enforcement to runtime, rather than install time. This brings
Android in line with the iOS model, by prompting the user to allow sensitive operations when
they happen, rather than approve a mile long list of permissions in bulk upon installation
(discussed more in Chapter 8), and greatly mitigates the potential for trojan apps surreptitiously
trying to access your personal information or camera, while entertaining you with a flapping
bird.

M also aims to improve on two drawbacks of its predecessors: Data encryption (which was
introduced with HoneyComb and enabled by default in Lollipop) is now extended to external
storage, by means of adopted devices. Power management - always a challenging issue - is
further improved with "Doze" mode, sleeping for long intervals between periodic wakeups for
app syncing and pending work. M also introduces App idle detection (somewhat reminiscent of
OS X's "App Nap" feature, which suspends apps which are not in use.

Other, more original features include Direct Share, App Linking, improvements to audio/
video syncing (including fast or slow motion playback), MIDI support, direct flashlight (torch)
support, camera API extensions, improved notifications, and significant enhancements for
"Android for Work". A full list of changes can be found on the Android Developer Website
(http://developer.android.com/preview/api-overview.html).

If Google is true to their own advertised schedule, M may overtake Lollipop, (whose
adoption rate is still dwindling in the low teens, as best) . Vendors may choose to wait a bit,
rather than have to go through the long process of upgrading to Lollipop - only to be forced to
upgrade again when M comes out shortly after.

---

**Page 7**

Chapter |: Introduction

Experiment: Figuring out your device's Android version

Though vendors customize Android in a variety of ways, the basic underlying system is
the same. Most Android users are familiar with the Settings >> System >> About Phone
GUI, which provides details about the Android version used*. The relevant class is
com.android.settings.DeviceInfoSettings (found under the AOSP's
packages/apps/settings), which uses the android.os. Build class. The values, however,
are obtained from system properties, so an often simpler way of getting to those values is
directly, using the getprop tool. This is shown in Figure 1-1:

Figure 1-1: Mappings between the Settings app DeviceInfoSettings and system properties

% 4 3:51
€ About phone Q
r
Legal information
Model number
dk_phone_armv Build. MODEL = getprop(“ro.product.model”)
Android version
Build.RELEASE = getprop(“ro.build.version.release”)
Baseband version getprop(“gsm.version.baseband”)
Kernel version
‘A ms 01 a 5 Data obtained from /proc/version
J
Build number
sdk_phone_armv7-eng 5.0 LRXO09D 1504858 test Build. DISPLAY = getprop(“ro.build.display.id”)
keys

The property settings, which are generated from the AOSP and placed into /system/
build.prop, hold true on modified builds as well - even those as heavily customized as
Amazon's "FireOS". The most useful properties are ro. build.version.sdk (API version),
and ro.build.fingerprint, which is itself an amalgam of several other properties, for
example:

generic/sdk_phone_armv7/generic:5.0/LRX09D/1504858:eng/test-keys

Property Describes
ro.product.manufacturer Vendor id
ro.product.name Device code name. For Google - fish names

ro. build. product:version.release | Product name and Android base version

ro. build.id first letter: version (rest described in the documentation*)
ro. build. version.incremental Internal build number, auto-incremented by AOSP build system
ro.build.type user: user facing, eng: Engineers/internal

release-keys: production system, actual certificates.

ro.build.tags test-keys: development

* - As of JellyBean, the "Build Version" provides the backdoor functionality to the Developer Settings (which include
ADB), by clicking seven times on the view.

---

**Page 8**

Android Internals::A Confectioner's Cookbook (Volume 1)

Android vs. Linux

Not just another Linux Distribution

Linux, the core of Android, has been around for well over a decade before Android was
even conceived. Linux is a fully open source operating system, whose kernel started as a
Master's Thesis of one, Linus Torvalds, and has since gained worldwide fame and adoption. A
kernel alone, however, does not a full operating system make. Torvalds decided to release his
work as open source, and attracted developers who extended it further, by providing
components for it - binaries both ported from other UN*X systems, as well as original ones.
Linux exploded in popularity as a free alternative to the expensive UN*X systems of the time,
effectively undercutting them and leading to the demise of most.

Along its rapid evolution, Linux attracted commercial interest. Companies, whose sole
purpose was to package the kernel along with additional binaries, sprouted and provided
"distributions" of Linux. These companies often provided Linux for free, basing their entire
business model on support. At times, "professional" or "enterprise" grade distributions,
containing custom tweaks or specialized tools, were provided, costing money to license.

Linux quickly became the de facto operating system of the embedded space. Contrary to
other players in the field, such as Windows CE (which required too many resources), and real
time operating systems such as PSOS or VxWorks (both of which involved heavy licensing fees),
Linux offered a platform that was not only free, but fully customizable and light weight. One
company, MontaVista, based its entire business model on porting Linux to the embedded space -
notably, the ARM, MIPS and PowerPC architectures. The port provided for Embedded platforms
the same functionality as that which was provided on the desktop - a fully featured shell
environment. All for a generous licensing fee.

But developers needed more. Long gone are the days of shell interfaces, and all users (save
for battle-hardened veterans) expect a graphical user interface from their operating system.
Linux relied on X-Windows, the traditional UN*X Windows architecture, for its GUI. Setting up a
GUI on an embedded platform was far from straightforward. Graphics programming using X-
Windows API was also quite cumbersome. Additionally, vendors such as Montavista provided
just the basic platform. Developers still had to port additional components and create their own,
often having to start from scratch.

And then came Android.

Google spotted the promise in a mobile operating system back in 2005, when they
acquired Android, then a small startup by Andy Rubin. Android disappeared off the map, till
its resurgence some years later (shortly after Apple's "iPhoneOS"). Mobile vendors, trying to
adapt to the revolutionary device, quickly wanted to provide a similar experience - and
needed to catch up quickly.

Android's novelty arises from what it aims to provide - not just another Linux distribution -
but a full software stack. The term "stack" implies several layers. Android provides not just
the basic kernel and shell binaries, but also a self-contained GUI environment, and a rich set of
frameworks. Coupled with a simple to use development language - Java - Android gives
developers a true Rapid Application Development (RAD) environment, as they can draw on pre-
written, well-tested code in the frameworks to access advanced functionality - such as Cameras,
motion sensors, GUI Widgets and more - in a few lines of code. With features that at first
borrowed heavily from iOS and later improved on them, Android became the de-facto OS for
Mobile, much as Windows is for the Desktop, or Linux was elsewhere.

---

**Page 9**

Chapter |: Introduction

Android has since had its hegemony constantly reinforced by the feedback loop of its
ecosystem - Android's "App MarketPlace", (which quickly followed Apple's "App Store"), adopted
that model to allow developers to quickly distribute their apps in a manner far more (and some
would say, too) relaxed with virtually no hurdles. The result is that Google Play (as the
MarketPlace is now known) has surpassed the App Store and offers millions of apps. Adopting
Android provides a mobile vendor with instant access and compatibility with those apps, but only
if they comply with Google's Mobile Application Distribution Agreement (MADA), which mandates
full integration of Google's apps and services.

In a sense, Android has done to MontaVista and other Embedded Linux firms what Linux
has done to UN*X and other competitors - undercutting by providing a totally free alternative.
Google pushes Android for free, with no licensing fees (at least, for now), and fairly relaxed
terms of use (though those are getting tighter, slowly but surely). It's no wonder, then, that
Android has risen in only a few years to achieve almost total hegemony of about 80% of the
global mobile market, leaving only a persistent bastion of iOS (presently at about 20%), along
with nigh-insignificant dregs of Windows Mobile and BlackBerry. A mobile vendor basically has
only very limited options in a choice of operating system: develop a homegrown one, or go with
a ready made one. Nearly all opt for the latter*, and then the choice boils down to Android, or
Windows Mobile. Microsoft has tried to follow the Android model and offer its system for free -
but the effort was too little, and far too late - as it lacks the ecosystem. BlackBerry, on its own
part, has ported the Android runtime to its own OS, hoping to win back market share by
providing runtime compatibility with the multitude of Android Apps.

Commonalities and Divergences from Linux

Android is built on top of Linux, but modifies it in substantial ways - including some which
break compatibility with the mainstream. The Android kernel source tree diverged from the
mainline kernel around version 2.6.27, but has been converging since version 3.3. In user-
mode, Google maintains the frameworks and runtime of the AOSP (Android Open Source
Project) in an entirely separate repository. From a high-level perspective, though it's hard to
quantify exactly how much the two OSes differ, a safe estimate would be that Android and Linux
are about 95% alike at the kernel level, and about 65% or so at the user-mode.

This guesstimate is drawn by taking into consideration that, at the kernel level, aside from
a few differences (ARM platform and drivers not withstanding), the rest of the kernel source is
unmodified. Those differences (which include IPC, memory and logging enhancements) are
collectively referred to as Androidisms, and most have in fact by now been merged into the
mainline - either replaced with similar kernel functionality, or included in the drivers/staging/
android) directory.

At the user-mode level, there is more of a divergence, introducing two entirely new
components - the Dalvik runtime and the Hardware Abstraction Layer - as well as replacing glibc
with Bionic, and providing a custom version of init, the system startup daemon. The underlying
OS, however, still remains for the most part unmodified, with native binaries, processes and
threads behaving as they do on Linux. This enables the approach taken in this book, of
discussing low-level Linux-based approaches for debugging and tracing, as is discussed in
Chapter 7.

Android also makes more clever use of features present in Linux, though left unused in
most desktop distributions. These include control groups, low-memory conditions (Linux OOM,
which Android expands on with its Low Memory Killer), and security features - capabilities and
SElinux (as discussed in Chapter 8).

Android also uses quite a few open source projects which were of limited popularity in
Linux, but form the backbone of its feature set. These projects (in the external/ folder of the
AOSP) are largely responsible for implementing Android's network capabilities, and include
racoon (vpn), mdns (service discovery and Wi-Fi Direct), dnsmasgq and hostapd (tethering
and Wi-Fi Direct), and wpa_supplicant (Wi-Fi). Other open source projects provide library-
level support (discussed and shown later in Table 1-3).

* - Mobile device vendors are becoming increasingly uneasy with several shortcomings of Android: The first, is the common
feature base, which makes it hard to differentiate their product from others. The second, is increased dependency on
Google, which actually strives to enforce the Android look and feel across devices. Lastly, Google's Mobile Application
Distribution Agreement (MADA), which forces the inclusion of all Google Apps in order to gain access to the Play Market.
This has led some vendors (notably, Samsung) to look at alternatives (e.g. Tizen). At present, Android seems to be fully
entrenched and not likely to lose dominance any time soon.

---

**Page 10**

Android Internals::A Confectioner's Cookbook (Volume 1)

Figure 1-2 compares and contrasts the software stacks provided by Linux and Android. We
then move to explore the notable differences, in turn.

Figure 1-2: The Android Architecture, compared with that of mainstream Linux

Android Linux

Applications

X-Windows

Native Libraries Native Libraries

GlibC

Hardware Hardware

The Android Frameworks

Android owes a key part of its success to its rich set of frameworks. Without them, Android
would have likely ended up as just another embedded Linux distribution (and would have in fact
gone the way of MontaVista, which was highly popular before Android made its debut). By
providing the frameworks, Android facilitates the application creation process, allowing
developers to use the higher-level Java language, rather than low-level C/C++. The addition of
the frameworks further expedites the process, as developers can draw on the plentiful APIs,
which handle graphics, audio and hardware access. Unlike X-Windows and GNOME/KDE, these
are far simpler, and operate in a much more straightforward manner.

Through the use of Java package naming, Android frameworks are divided into separate
namespaces, according to their functionality. Packages in the android.* namespace are
available for use by developers. Packages in com.android.* are internal. Android also supports
most of the standard Java runtime packages in the java.* namespace. Table 1-2 shows the
breakdown of the commonly used frameworks by package, sorted by the API version they were
introduced in, so as to give an idea as to the evolution of the operating system features. Note
that the table only shows when frameworks made their debut, and does not show their
expansion, which does occur in between API versions, as more classes are added.

---

**Page 11**

Chapter |: Introduction

Table 1-2: The Android Frameworks

Package Name API Contents
android.app 1 Application Support
android.content Content providers
android.database Database support, mostly SQLite
android.graphics Graphics support
android.opengl OpenGL Graphics support
android.hardware Camera, input and sensor support
android.location Location support
android.media Media support
android.net Network support built over java.net APIs
android.os Core OS Service and IPC support
android.provider Built-in Android content-providers
android.sax SAX XML Parsers
android.telephony Core Telephony support
android.text Text rendering
android.view UI Components (similar to iOS's UIView)
android.webkit Webkit browser controls
android.widget Application widgets
android.speech 3 Speech recognition and Speech-to-Text
android.accounts 4 Support for account management and authentication.
android.gesture Custom gesture support
android.accounts User account support
android.bluetooth ° Bluetooth support
android.media.audiofx Audio Effects support
android.net.sip 9 Support for VoIP using the Session Initiation Protocol (RFC3261)
android.os.storage Support for Opaque Binary Blobs (OBB)
android.nfc Support for Near Field Communication
android.animation Animation of views and objects
android.drm 11 Digital Rights Management and copy protection
android.renderscript RenderScript (OpenCL like computation language)
android.hardware.usb USB Peripheral support
android.mtp 12 MTP/PTP support for connected cameras, etc
android.net.rtp Support for the Real-Time-Protocol (RFC3501)
android.media.effect Image and Video Effects support
android.net.wifi.p2p 14 Support for Wi-Fi Direct (Peer-To-Peer)
android.security Support for keychains and keystores
android.net.nsd 16 Neighbor-Service-Discovery through Multicast DNS (Bonjour)
android.hardware.input Input device listeners

* - This table, while detailed, is not comprehensive, and only reflects the more important classes. A full list can be found at
http://developer.android.com/sdk/api_diff/##/changes.html, replacing ## with the API level

10

---

**Page 12**

Android Internals::A Confectioner's Cookbook (Volume 1)

Table 1-2 (cont.): The Android Frameworks

Package Name API Contents
android.hardware.display 7 External and virtual display support
android.service.dreams "Dream" (screensaver) support
android.graphics. pdf 19 PDF Rendering
android.print[.pdf] Support for external printing
android.app.job Job scheduler
android.bluetooth.le Bluetooth Low-Energy (LE) support
android.hardware.camera2 The new camera APIs
android.media.[browse/projection/session/tv] a Media browsing and TV support
android.service.voice Activation by "hot words" (e.g. "OK Google")
android.system uname (), poll (2) and fstat [vfs] (2)
android.service.carrier 22 SMS/MMS support (CarrierMessagingService)

In practice, the entire set of frameworks is bundled into several Java ARchive (.jar) files on
the device, in /system/framework and - in L - precompiled into the boot.art file. Although
the AOSP is open source, it can come in quite handy to locate a package directly in the JAR

itself, which you can do by invoking dexdump (or the dextra tool) on the classes.dex files
inside the JARs.

The Dalvik Virtual Machine Figure 4-3: De sik, teglanelspliove by Son
“ DALVIK
Android's other notable addition is the Esai
introduction of the Dalvik Virtual Machine. This VM
became key to making Android workable on mobile
devices back when 256M of memory was considered
"plenty". Dalvik was not the first type of Virtual
Machine to be attempted on mobile devices - Sun
Microsystems hoped to push Java 2 Mobile Edition gy serra
(J2ME), but with very little success.

BEEOHOD -

falafel olalaelolotaaletolal ames

Dalvik is largely the brainchild of Dan Bornstein, :
whose Google I/O 2008 presentation serves as a great reference as to its 5 design. The name -
Dalvik - was chosen in honor of a fishing village in northern Iceland.

The Dalvik VM, though seemingly java-esque, is actually not a Java Virtual Machine. Though
not too far-removed from one, it runs a different form of bytecode (called DEX, for Dalvik
Executable), and is more optimized for efficiency and sharing memory than the JVM designed by
Sun/Oracle. Those very optimizations enabled it to prevail despite the strict constraints of mobile
platforms, which have felled Java (specifically, J2ME) from gaining ground outside limited
implementations.

Android used a subset of the Apache Harmony files as basis for its core classes. Harmony
was chosen as a free (Apache-license) open source clone of (then Sun's, now Oracle's) JVM.
Oracle actually sued Google in 2010 for never properly acquiring a license for the Java class
libraries, and the saga is far from conclusion even in early 2015.

As this book goes to print, Dalvik is being superseded by the Android RunTime (ART),
as described later in this chapter. Contrary to popular belief, however, this does not mean
Dalvik is going away: Only the Just-In-Time (JIT) compilation aspect of it has been
replaced, but the file format (DEX) is still very much alive, as are the key architectural
concepts. We therefore discuss both Dalvik and ART in great detail in Volume II.

11

---

**Page 13**

Chapter |: Introduction

JNI

Android Applications run in the virtual machine, but at times need to escape it - usually to access
hardware or other device (or chipset) specific features. Dalvik therefore allows the inclusion of native
libraries (ELF shared objects) in application code, through the Java Native Interface (JNI).

Android has somewhat of a love/hate relationship with JNI. No doubt vendors would be happier
with pure Dalvik applications, as those are confined in the VM, and thus remain agnostic to the
underlying architecture. In this way, Android applications would run universally - on Intel, ARM, MIPS,
and other architectures - with no modification. On the other hand, the VM environment is not without
its limits (especially when it concerns graphics) and drawbacks (notably decompilation). It is therefore
not at all uncommon to see JNI used in applications optimizing for performance, or seeking resistance
to reverse engineering. Google therefore provides the Native Development Kit (NDK) (downloadable
at Android Developer!*), which developers can use to build native libraries (and binaries).

Not all applications use JNI, but in those that do, JNI libraries can be easily seen in the package
(.apk) since they are in a separate folder: //ib/architecture. A good example of this can be found
in the DropBox App* (here in an output from a Galaxy Tab 3 10.1), providing JNI support for no less
than four different architectures:

Output 1-1: Demonstrating JNI Libraries in an APK

ip -1 /system/a
lib/ar

JNI normally works seamlessly across ARM devices (which comprise the vast majority),
though processor version differences (e.g. ARMv6, ARMv7) do require different libraries (hence
"armeabi" and "armeabi-v7a" in the output). When it comes to x86 architectures, JNI is a
major headache for Intel, who would like to see more vendors use its chipsets for Android.
Rather than depend on the app developers to compile an x86 specific version (most don't),
Intel provides a closed-source ARM emulation called Houdini (extending Dalvik/ART, as
discussed later in Volume II) as part of their Android distribution. This emulator, (along with a
few minor modifications in Dalvik), enables ARM native libraries to work on Intel architectures.

Native Binaries

From the Linux perspective, all executables are ELF binaries. Android's critical system
component are implemented in C/C++, and are compiled into native binaries. User applications
are compiled into Dalvik bytecode, but the bytecode runs (or, in ART, is compiled ahead-of-
time) in the context of a Dalvik Virtual machine, which is, in and of itself, an ELF binary. Thus,
while most developers remain oblivious to binaries, they nonetheless play an important role in
Android.

Binaries are usually located in /system/bin, and /system/xbin (with a few critical
binaries located in /sbin). Most binaries are usually the same across all devices, being part of
the AOSP, but it is not uncommon to find additional binaries from the vendor or chipset

manufacturer (e.g. modecision, on Qualcomm MSM multi-core devices). You can see a list
of processes loaded from native binaries at any time by filtering the ps command. This is
shown in Output 1-2 (from an HTC One M8), with the AOSP binaries highlighted:

* - Not to be confused with the commercial app of the same name, used to for cloud storage

12

---

**Page 14**

Android Internals::A Confectioner's Cookbook (Volume |)

Output 1-2: Native binaries executing on an an HTC One M8

shell@htc_m8wl:/ $ ps _
root 1

root 218
root 365
system 367
root 368
radio 369
system 370
root 371
373
375
376
379
380
384
387
388
389
390
391
393
395
397
400
404
505

install
keystore
shell
root
root
root
system
root
system

grep " /" | cut -cl-22,55-

init
/sbin/ueventd
/sbin/healthd
/system/bin/servicemanager
/system/bin/vold
/system/bin/rild
/system/bin/surfaceflinger
/system/bin/pnpmgr
/system/bin/rmt_storage
/system/bin/qmuxd
/system/bin/netmgrd
/sbin/tpd
/system/bin/netd
/system/bin/debuggerd
/system/bin/drmserver
/system/bin/mediaserver
/system/bin/installd
/system/bin/keystore
/system/bin/dumpstate
/system/bin/thermal-engine
/system/bin/memlock
/system/bin/clockd
/system/bin/qseecomd
/system/bin/cand
/system/bin/qseecomd

# QCOM specific
# QCOM specific

QCOM specific
HTC specific
HTC Specific
QCOM Trust Zone

QCOM Trust Zone

844
847
848
850
851
852
868
919
1170
1171
1631
1637 1
12277 12149
23853 1

media_rw
system
root
nobody
system
root
root
media
root
wifi
media_rw
root
shell
camera

/system/bin/sdcard
/system/bin/time_daemon
/system/bin/dmagent

QCOM specific

HTC specific: QCOM DIAG
QCOM Quich charge supp
QCOM WLan

HTC Specific

/system/bin/wenss_service
/system/bin/htc_ebdlogd
/system/bin/logcat2
/system/bin/adsprpcd
/system/bin/logwrapper
/system/bin/wpa_supplicant
/system/bin/sdcard
/system/bin/mpdecision
/system/bin/sh
/system/bin/mm-qcamera-daemon #

QCOM Application DSP

170

PRPRPRPORPRPRPRPP APPR PEP BPBPPPRPRPRP PPP PPP PEPPER RO

QCOM SMP Policy

QCOM camera support

Because ELF is a standard file format, you can use any of the Linux ELF parsing tools (such as

readelf, objdump, or other tools in the set of binutils) to handle the Android binaries. The
Android NDK provides the full toolset (cross compiled so it can run on the host) in the
toolchains/directory, supporting x86, MIPS, ARM and - as of ri0d - ARM64 - as shown in Output

1-3: Output 1-3: Locating the Android NDK's binutils

# replace "arm-linux-androideabi-4.9" with "aarch64-linux-android-4.9" for 64-bit ARM
morpheus@Forge (~)$ 1s $NDK ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86 64/bin
arm-linux-androideabi-addr2line arm-linux-androideabi-gcc-4.6 arm-linux-androideabi-objcopy
arm-linux-androideabi-ar arm-1linux-androideab arm- 1linux-androideabi -obj dump
arm-linux-androideabi-as arm-linux-androideabi-gdb arm-linux-androideabi-ranlib
arm-linux-androideabi-gprof arm-linux-androideabi-readelf
arm-linux-androideabi-ld arm-linux-androideabi-size
arm-linux-androideabi-ld.bfd arm-linux-androideabi-strings
arm-linux-androideabi-ld.gold arm-linux-androideabi-strip
arm-linux-androideabi-ld.mcld

arm-linux-androideabi-nm

arm-1linux-androideabi-c++
arm-linux-androideabi-c++filt
arm-linux-androideabi-cpp
arm-linux-androideabi-elfedit
arm-linux-androideabi-g++
arm-linux-androideabi-gcc

13

---

**Page 15**

Chapter |: Introduction

Bionic

Contrary to Linux distributions, which use GNU's LibC (GLibC) as their core runtime (the familiar
libc.so), Android elects to use its own C-runtime library, which is called Bionic. This is touted as
being motivated chiefly by simplicity’, though in practice there is a legal consideration as well - The
GNU public license (GPL) places limitations on code which can use GLibC (similar in some respects to
GPL portions in the kernel), and Google sought to avoid that™. Bionic is open source, but uses a

hybrid of the BSD license (which is far more permissive for third party linkage) as well as Android's
own license.

Omissions

Legal issues aside, Bionic is more lightweight than GLibC, and more efficient for Android's
purposes, leaving out features deemed unnecessary or too complicated. Notable omissions are:

e Streamlined system call support: Since system calls are called frequently, Bionic aims
to optimize them by providing the thinnest wrappers possible. The system call stubs are
generated with the help of bionic/libc/SYSCALLS.TXT. Some system calls are not at all
exported.

e No support for System V IPC: Among the system calls not exported by Bionic are those
dealing with UN*X System V Inter-Process-Communication (sem[ct1l|get|op] and
Shared Memory (shm [at | dt |get|ct1). This was a design decision in Android,
deprecating these forms of IPC in favor of Android's own (ASHMem and Binder, described
in Volume II).

e Limited Pthread functionality: On the one hand, Pthread support is built-in to Bionic
(i.e. not a separate libpthread.so). On the other, the pthread support is not full, with the
most notable feature missing is support for thread cancellation, via pthread_cancel.

Mutex support is also stripped down, made more efficient by relying on the kernel's fast
mutex (the futex(2) system call), but higher level IPC objects (e.g. rwlocks) have been left
out.

¢ Limited C++ support: Though C++ is supported (indeed, most of Android's code is
written in C++), exceptions are not. Likewise, the Standard Template Library (STL) is not
included, though there is no restriction for linking against it manually (a port can be found in
external/stlport project).

e No support for Locales and/or wide characters: Bionic natively needs only ASCII,
though Unicode is also supported via libutils.so

The omissions make sense, considering that most code is meant to be done in the virtual
machine, and the VM itself is written to avoid needing these functions: For example, the VM has its
own thread management and Unicode support (via ICU). These omissions do, however, pose
challenges to native code developers, especially those who seek to port libraries and executables
from Linux to Android, as we discuss later.

Additions

Bionic also adds quite a few features to the standard LibC, which are optimized for Android.
These include:

e System Properties: Properties are a unique feature of Android, which allow both the
system as well as applications to supply various configuration and operational parameters
in a simple key/value store. This is similar to the notion of Java properties (and, in fact, is
accessible through Java's System.properties). Android relies heavily on this
mechanism, which is supplied through a shared memory region, accessible and read-only
to all processes on the system, but settable only through /init. We discuss the
implementation of properties in Chapter 4.

* - Google is avoiding GPL and licensing issues not just in Bionic, but in other components (e.g. udevd). GPL has
strict (legal) restrictions requiring linkage with likewise GPL open source components. Avoiding GPL maintains an
option for them to close the source at any time in the future (as they did once with parts of Honeycomb).

14

---

**Page 16**

Android Internals::A Confectioner's Cookbook (Volume 1)

e Hard-coded UID/GID implementation: Rather than rely on the passwd and group files as
traditional UN*X does, Android opts instead to hard-code the ids, and emulate getpwnam(3)
and friends. The reasoning for this becomes clear when Android's security model is considered:
Every application is assigned its own UID and GID (beginning with 10000) and those IDs are
then mapped to the human readable app_uXXxX (or, as of JellyBean, uUXX_aYYY) format.
Additionally, Android reserves the lower UID/GID range (1000-9999) for its own subsystems. The
AIDs (defined along with directory permissions in android filesystem config.h) are described
in more detail in Chapter 8, which deals with security.

e Built-in DNS resolution: Bionic integrates the DNS name-to-IP resolution code
(traditionally in libresolv.so). The code used in Bionic is more secure (randomizes both source
port and query ID, to mitigate birthday attacks), and introduces a novel feature - per-process
DNS resolution. This allows capturing and redirecting DNS requests by specific applications,
through the definition of net.dns.pid system properties. The DNS configuration itself is also
stored in properties (net.dns#). The nsswitch.conf, which on Linux allows name resolution
through alternate protocols (e.g. NIS, LDAP) is understandably not supported, though
resolv.conf is still supported (in /system/etc).

¢ Hard coded services and protocols: Doing away with libresolv.so entirely, Android

removes support for the protocols and services files (commonly found in /etc on UN*X), and
emulates getservent (3) through its internal __ res_ get_static(). Other APIs, such as

getprotoent (3), are not supported.

Porting Challenges

As with the omissions, the additions pose a challenge when trying to port code the other
way around - that is, from Android to Linux. If these could be overcome, one could ostensibly
port Dalvik to Linux or other OSes (as indeed some developers have, discussed in Volume II),
and have Android apps working on desktops, as well.

Bionic presents the main hurdle for porting code to and from Android. While to some extent
compatible with GNU LibC, the additions and omissions described above do mean that some
more advanced features - notably multithreading - will not port. For some source packages,
however, all it takes is recompilation with the NDK. In this way, many tar ball packages can be
ported for Android as well, tweaking the configure script and Makefile.

Keeping in mind both Android and Linux export the same system calls, it should come as no
surprise that statically linked binaries are often fully compatible (keeping in mind the same
underlying CPU architecture). Static linking imports the specific dependencies from the various
libraries into the core of the executable. A noteworthy example is Intel's Houdini (discussed in
Volume II), which is provided on x86/64 versions of Android. A more common example still is
BusyBox, which is an all-in-one binary supplying various shell command functionality: An ARM
compiled static binary of Busybox taken from embedded Linux is mostly compatible, although
minor aspects (such as displaying Android AIDs) don't always work well.

It's worth noting that there are open issues in Bionic, specified in bionic/ABI-bugs.txt,
which affect some esoteric, but nonetheless potentially important datatypes, such as (at the time
of writing) time_t (32-bit time, which will blow up in 2038) and of £_t (32-bit file offsets).
Also, Bionic itself is optimized for 32-bit, and Apple's move to 64-bit will force Bionic (and,
indeed, all of Android) to be ported to 64-bit, as is already the case with L, and discussed later in
this chapter.

15

---

**Page 17**

Chapter |: Introduction

Android Native Libraries

In addition to Bionic, Android contains quite a few other important libraries, which provide
runtime support for Dalvik, the frameworks, and the system processes. Those are strewn around the
source tree, so the following classifies them by the directories they are in .

Core Libraries

The libraries in system/core mostly provide wrappers over kernel Androidisms, or implement
additional functionality in user-mode, and include:

e libcutils: Provides convenient support functions for kernel exported data (e.g. /proc/cpuinfo),
socket support, and Androidisms such as ASHMem.

e liblog: Which wraps the Android /dev/log mechanism, to provide a fast and efficient, ring-
buffer based mechanism for logging.

e libion: Wrapping the ION Memory Allocator, which was introduced in ICS.
e libni 2: Which wraps the Linux NetLink socket mechanism.

e libpixelflinger: Used primarily by the SurfaceFlinger (the core of Android's Graphics stack,
described in Volume II). "Flinging" refers to the act of composing two or more inputs so that
in the case of graphics, for example, the resulting pixel is a (potentially alpha-blended) color
combination of the ones merged.

e libsuspend: Which abstracts some aspects of power management, particulary those relating
to sleep and suspension of the operating system.

Lesser libraries include:

e libdiskconfig: Abstracting disk (flash) configuration and partition management.

e libcorkscrew: Used by the debuggerd to unwind stacks and symbolicate application crashes
("tombstones").

e libmemtrack: providing process memory tracing services, with the help of hardware
modules, if any.

e libmincrypt: providing basic implementations of RSA and SHA-[1|256], required for digital
signature processing.

e libnetutils: Simplifying interface configuration and DHCP support.
e libsync: Which wraps the kernel's sync Androidism.

e libsysutils: Provides primitives used by system utilities. Includes
Framework([Client|Listener|Command], Netlink[Event|Listener], Socket[Client|Listener] and
ServiceManager

e libzipfile: Providing wrappers over zlib to handle zip files. Android uses zip extensively, with
application packages (.apk files) being a special case of zip.

16

---

**Page 18**

Android Internals::A Confectioner's Cookbook (Volume 1)

Framework support libraries

Libraries in frameworks/ provide native support services for the Android frameworks.
Despite not being part of the "core", they are nonetheless important, and further classified by
subdirectories.

e The frameworks/base/core/jni directory contains the very important libandroid_runtime.so,
which provides the low level JNI support for the Dalvik VM. The directory contains the JNI
components of over 85 framework (Dalvik-level) classes.

e The frameworks/base/services/jni directory contains the equally important libandroid_servers.so,
which provides the low level JNI support the Android services.

e The frameworks/base/native/android directory contains libandroid.so, which provides a native
interface to assets, storage manager, and more.

e Libraries in base/libs include libandroidfw.so and libhwui.so. The former provides miscellaneous
support services such as zip file parsing and asset managements. The latter provides
hardware accelerated UI rendering, via OpenGL and SKIA.

e Libraries in av handle media, audio and video. These include:

° Camera HAL libraries - libcamera_client.so and libcamera_metadata.so (q.v. Volume II)

o DRM Framework support (libdrmframework.so) supporting Android's Digital Rights
Management mechanism.

o Media support libraries - including libeffects.so, libmedia.so, libnbaio.so,
libmediaplayerservice.so, and libstagefright.so.

The subdirectory av/services contains further support libs for services -libcameraservice.so,
libaudioflinger.so and libmedialog.so.

Libraries in native/libs include:

e
o libbinder: Binder support functions, discussed in depth in Volume II.
o libdiskusage A tiny library providing directory sizing functions.
o libgui: Provides GUI abstractions (such as the surface), built on top of libui.so

o libinput: Provides basic primitives used by Android's input stack, as described in
Volume II.

o libui: Provides the native APIs for Windows and Buffers, used by surfaceflinger (not
user events).

The native/ subdirectory also contains the opengl/ directory, which hold EGL and
OpenGLES, discussed in Volume II).

External Native Libraries

Android relies on quite a few "external" libraries. The name refers to their location in the
Android source tree, and the fact that they are not formally a part of Android - rather, they are
open source projects which lend powerful capabilities to the operating system.

There are well over 150 such external projects in the Android source tree, so this work does
not make an attempt to cover them all. Table 1-3 nonetheless attempts to touch on the
important ones, providing library support:

17

---

**Page 19**

Chapter |: Introduction

Table 1-3: External library projects in the Android source tree

Directory Contents
bluetooth Bluedroid library (libbluedroid.so), which supports user-mode bluetooth capabilities
icu4c libicuuc and libicui18n, handling Unicode support and internationalization
mdnsresponder |Apple's Multicast DNS (Bonjour) - contains daemon (mdnsd) and library (libmdssd.so)
ibcepel SELinux support (JellyBean and later)
skia The SKIA 2D graphics library (discussed in Volume II)
sqlite The SQLite3 DB support, providing the core for many Android databases
SVOX libttspico and libttscompat, for SVOX Pico Text-To-Speech Engine
tinyalsa Minimal version of the Linux Advanced Sound Architecture (ALSA) library
webkit The webkit browser core, used by webview controls
zlib Zlib - a library providing compression support for gzip and the like

Note that, once deployed on the device, external libraries are largely indistinguishable from
those of the AOSP, since all libraries end up alongside one another in /system/1ib. Similarly, it
is possible your device has additional vendor-specific libraries in /system/1ib (though by

convention those should be placed in /vendor/1lib).

Hardware Abstraction Layer

Android is meant to run on so many types of different devices - tablet, phones, STBs,
treadmills, and what not - that the underlying hardware may greatly differ in its scope and
support. In an effort to combat this, Android defines a Hardware Abstraction Layer (HAL) which

aims to promote standardization by defining an adapter. Hardware vendors are free to implement

their own drivers in kernel mode, but must supply a shim, to conform to the interface Android
(and particularly, Dalvik) expects. The Hardware Abstraction Layer defines what an abstract

camera, GPS, sensor, and other components look like to Android. This does not preclude vendors

from extending or modifying functions - it only requires the vendor to drop the shim into /

system/lib/hw, and the HAL - libhardware.so will automatically load them. Output 1-4 shows

the HAL libraries used in the S5:

Output 1-4: Hardware Abstraction Layer libraries in the Galaxy S5

# 1s -1 /system/lib/hw

14-03-09 1

2dp.default.so

1
1 é
1
1
1
1 é
1
1
1
1
1
1
1
1

poser.

ore.def

5.msm8974

The Hardware Abstraction Layer is naturally a very important aspect of Android - both
because it represents a divergence from Linux, and because it is instrumental in supporting
the slew of Android devices. It is thus deserving of its own chapter, in Volume II.

18

---

**Page 20**

Android Internals::A Confectioner's Cookbook (Volume 1)

The Linux Kernel

The Linux kernel, due to its open source and free license nature, provides an excellent
substrate for Android*. Now parsecs away from Linus Torvalds' initial version, the kernel keeps
evolving at remarkable speeds, with new features added every weeks or months. Android's own
capabilities are significantly affected by the kernel's, with notable examples being compressed
RAM and 64-bit support. The latter helps explain Table 1-1, which pits kernel version 3.10 as the
minimum version for Lollipop: The kernel officially supports ARM64 (AArch64) as of 3.7.

Android kernels are compiled slightly differently than those of Linux, with the config files
being generated by merging Android's base and recommended configuration templates with
those of the default kernel distribution (as shown in the source.android.com website's kernel
section)’®.

As previously mentioned, Android introduces its own idiosyncrasies, or Androidisms, into the
kernel. A few of these are in the kernel core, guarded by #ifdef statements for conditional
compilation, with the rest being in drivers/staging/android directory. These Androidisms,
as of 3.10 and later, include:

e Anonymous Shared Memory (ASHMem): A mechanism to allow shared memory.
Applications can open a character device (/dev/ashmem) and create a memory region which
can then be mapped into memory. This is required to work around the restriction of no
world-writable directories and System V IPC.

e Binder: The crux of all IPC in Android. A legacy of BeOS, Binder presents a character device
(/dev/binder) which all applications can open. Android services register with Binder, and
clients can connect to them, with the help of servicemanager. Binder provides efficient,
advanced IPC, as discussed in Chapter 6, and explained in depth in Volume II.

e Logger: providing kernel-based ring buffers for fast, file-less logging. Android logs are
maintained by character devices in /dev/log. Android L augments this with a user mode
daemon, 1logd, discussed in Chapter 5.

e The ION Memory Allocator: Introduced in ICS, and offers efficient memory allocation to
kernel drivers and user mode alike (through /dev/ion). ION replaces an older Androidism,
PMEM, and aims to standardize memory management in the various SoC architectures.

e Low Memory Killer: A layer on top of Linux's own Out-Of-Memory (OOM) killer, which
terminates processes in case of memory exhaustion. While the latter is heuristic driven, the
former provides a more deterministic way of controlling process termination, and allows
defining memory pressure levels. Android L augments this with a user mode daemon, 1mkd,
discussed in Chapter 5.

e RAM Console: A mechanism for preserving kernel panic output (thread dump and last
dmesg (1) log). This has been deprecated in newer releases in favor of the Linux kernel's
own pstorefs (described in Chapter 2).

e Sync driver: The latest Androidism, introduced to allow fast synchronization primitives, used
primarily by Android's Graphics stack (in particular, surfaceflinger).

e Timed Output and GPIO: Allowing user mode programs to access GPIO registers from user
space, and automatically reset their values after a timeout. The main client of this is the
device vibrator functionality: The framework (via the HAL) can write a millisecond value into /
sys/classtimed_output/vibrator/enable, to start the device vibration, which automatically quiets
down after the timeout specified.

e Wakelocks: Originally a separate Androidism to control power management and prohibit the
kernel's sleep functionality, wakelocks have gradually been merged with the kernel's own
wakeup source mechanisms. (Power Management is detailed in Volume II, with a relevant
excerpt on the book's companion website).

* The kernel, in fact, provides a substrate for myriad Linux offshoots, including Samsung's Tizen, Jolia's Sailfish, Firefox OS,
and Ubuntu on Smartphones. All of these are seen as potential competitors to Android, though their market share, at least
as of early 2015, is infinitessimal.

19

---

**Page 21**

Chapter |: Introduction

Android Derivatives

Google offshoots

Google has made it clear that it wants to make Android ubiquitous in all kinds of devices - not
just phones and tablets. True to their vision, they announced three new offshoots of Android.

Android Wear

With rumors of Apple supposedly working on an Figure 1-4: Android Wear launcher UI
"iWatch", it's no surprise Google quickly rushed to announce
"Android Wear" back around KitKat. Android Wear is a version
of Android optimized for wearable devices (which, at the time of
writing, are a single-category domain, watches, though could
ostensibly be extended to other wearable devices). At the core,
Android Wear is the same Android used in phones and tablets,
but the home activity (main screen) has been replaced by a
simpler interface, owing to a watch's diminutive display. This
includes an emphasis on voice commands (by tapping on the

Google icon), notifications, and cue-cards. Some wear devices O
also support round screens, as well. / ) ©
Android Wear, identified by "clockwork" in the

ro.build.fingerprint property, can be thought of as a "slimmed down" version of Android.
Unnecessary frameworks and services have been removed, both to conserve memory, as well as
CPU (battery life being a major limiting factor of wearable devices). A comparison between the
phone and Wear flavor of KitKat reveals that all telephony services (phone, iphonesubinfo,
simponebook, isms), as well as print, appwidget, backup, usb, wallpaper, device_policy, and the
drmManager have been removed in Wear. Applications have likewise been slashed from over
180MB (in about 60 packages) to a mere 12MB in only 16 packages, leaving only watch specific
applications (ClockworkSetup.apk, ClockworkSettings.apk and the PrebuiltClockworkHome.apk

launcher), or those that can operate on a small screen (in other words, the default packages of

com.android.* from KK are not present or loaded in Wear). The SDK for Wear has been
released with documentation available in the Android Developer website?’,

Android Wear devices are, at present, designed to serve as satellites for more capable devices,
such as a smartphone or tablet. Their only connectivity is via BlueTooth, and most of their
frameworks are stubs, which connect to the full featured ones on a phone. Samsung, an early
adopter for its "Galaxy Gear" watch, is migrating away from Wear in favor of its homegrown Tizen,
citing issues with battery life and limited functionality as being the key drivers.

Figure 1-5: Android Auto UI (source: Google)

Android Auto

Shortly after Apple announced "CarPlay",
integrating iOS 7 with cars, Google happened

to announce "Android Auto", which aims to 39 minutes to Dolores

do surprisingly similar things: Provide a Park

convenient interface to use mobile devices in

cars, with access to useful apps such as ie Crossaver Oy

navigation, the music player, and (of course)

the phone. As with Android Wear, there's an Coming of Age

emphasis on voice commands and Foster tht People + Gooole Play buat

notifications - this time not because of screen
limitations, so much as the requirement for
hands-free operation.

20

---

**Page 22**

Android Internals::A Confectioner's Cookbook (Volume 1)

From the developer perspective, the important difference is that there is no need for a separate
car-specific UI. In fact, there's no need for any UI in Android Auto, because the built-in system UI
communicates with specific aspects of app functionality, and presents them as the "drawers", which
are list driven menus. This enables the driver to select functions with the navigation buttons found
on most steering wheels. Apps can still customize the built-in UI, by specifying icons and background
images, but don't need to display any custom UI Views, as they would normally. Developers need

to declare an additional XML file, with an automotiveApp element, and specify which features
they use - with "media" and "notification" presently being the supported features.

The XML file is connected to the App via a meta-data element in the App's
AndroidManifest .xml1, specifying the com. google.android.gms.car.application
reserved value for the name attribute.

Google has detailed the interface changes, such as the launcher, and the drawer-based UI
at the Android Auto website’®,

Android TV

TV Makers have long been using proprietary OSes to run their device - Samsung's Tizen and
LG's WebOS (formerly Palm/HP's) being the two most prominent examples. Google wishes to
extend Android's hegemony into this space, as well (gaining the fringe benefits in the trove of user
viewing habits). This is Google's second attempt at entering television, with their "Google TV" being
less of a niche product than "Apple TV" is.

Android TV has been announced and released alongside Android L, with ample documentation
on the Android TV website!9. From the emulator images, one can discern the main difference is in

the launcher (com. android.mclauncher, in /system/app/LeanbackLauncher.apk), the built
in TV app (com. android.tv, in /system/priv-app/TV.apk), and the TV Content provider

(com. android. providers.tv in /system/priv-app/TvProvider.apk). The content provider
exports URIs in android.media.tv for input (the remote control), channel, program and
watched_program. The latter three are stored in the provider database,
/data/user/0/com.android.providers.tv/databases. Other features have also been adapted for
TVs, notably remote-control based navigation, and huge screen sizes.

Android TV will likely evolve considerably in the future (perhaps evolving to compete
with Apple's plans for extending Apple TV and iOS). Future enhancements would likely
involve better streaming support, enhanced EPG (Electronic Programming Guide)
functionality, integration with ChromeCast, and gaming platform support. But there is
another foe to consider in the TV space -Amazon.

Non-Google ports

Because of its open nature, vendors are free to customize Android in oh-so-many ways. Most
enhance (or detract) from the standard UI, in an effort to differentiate their device from "yet
another Android". Notable examples include HTC and Samsung, with their "Sense" and TouchWiz
UIs, repectively. Others pack Android into new types of devices - for example NVidia with their
Shield console. In all the above cases, however, the base system is still very much the same
Android. Further, Google provides the "Compatibility Test Suite" (cts/ subtree of AOSP), which
vendors must pass in order to get the official blessing (and be assured that apps will function
correctly). Additionally, Google makes the Play Market inseparable from its other services. As an
price to enter the ecosystem, vendors must bundle the entire set of Google utilities - Maps, Mail,
etc - making it more likely the device will be tied to a Google account (and thus, an identity).

Other vendors, however, only take Android as a substrate, and make vast modifications.
They willingly give up the ecosystem, because they often create their own. One such example is
Chinese smartphone maker XiaoMi, whose top-of-the-line devices at rock-bottom prices has
propelled it to be one of China's (and possibly the world's) largest. XiaoMi built an entire
business by investing in its own ecosystem, and has willingly abandoned Google's services, most
of which are blocked in China anyway. One can imagine Google can't be too happy with it
(missing out on order of 100 million or more users), but this is just a consequence of Android's
open source nature. And it could be worse -Nokia, for example, experimented with versions of
Android that have been "converted" to Microsoft's cloud services. And on this side of the ocean,
there's Amazon.

21

---

**Page 23**

Chapter |: Introduction

FireOS

Amazon is one of the vendors that has no doubt benefitted the most from Android. The giant
retailer made its foray into the tablet market with its Kindle line, which was based on a proprietary
embedded Linux distribution, and an e-Ink display. With the Kindle Fire, Amazon modernized their
tablet, using Android as the core operating system.

Much to Google's chagrin, however, Amazon fully customized their version of Android, and
rebranded it as "FireOS". The interface was entirely revamped (sporting a "carousel" like selection of
apps), the devices are locked and keyed to Amazon only - effectively useless without an Amazon ID,
and any trace of Google - search, Play store, accounts, or otherwise - has been eradicated.

From a technical perspective, FireOS's core is still very much Android. Changes in it,
however, are quite radical and include removal of all things Google, and replacement with
Amazon. Specifically:

e Carousel as the home activity: The familiar Android launcher has been replaced by Amazon's
custom launcher, com.amazon.kindle.otter.

e Default Browser is "Silk": or, by its other name, com.amazon.cloud9. This is a WebKit based
browser, heavily modified and optimized to use Amazon's Elastic Compute Cloud (EC2) to
optimize web browsing.

e Google Play replaced by Amazon App Store: Internally referred to as com.amazon.windowshop
and com.amazon.venezia.

e Amazon Offers as screen saver: Utilizing Android's "Dreams" functionality to install a screen
saver filled with ads. Internally, this is done by several components in the com.amazon.dcp
package, and ads stored in /data/securedStorageLocation/dtcp/ (incidentally, revoking
permissions on this folder effectively disables ads).

e Aggressive OTA updates: The com.amazon.dcp package contains a host of services meant to
ensure the device is constantly up to date. Unlike other Android versions, FireOS doesn't ask
to update - it just goes ahead and does so. (Automatic updates are explained in Chapter 3)

Amazon has taken several pages from Apple's playbook, most notably locking down the system
to resist rooting (or at least, try) as well as prevent downgrading of the operating system once an
update has been installed (which it often is, automatically). With FireOS as a whole, Amazon steps
further away from the Google vision of Android, launching its own "Fire Phone", and its "Fire TV",
each with proprietary interfaces and APIs.

Headless Android

Take Android, and remove Dalvik and its accompanying frameworks, and you are left with a
operating system that has no GUI support, nor any use for an ecosystem. Such an OS, however, is
still valuable in its own right, as a base embedded Linux distribution, which has already been
adapted to work with ARM and MIPS processors. Before the advent of Android, embedded Linux was
a complicated and highly difficult environment, owing in large part to the complexity of building the
cross-compiler toolchain, and the user mode libraries. Companies which provided this toolchain and
environment (along with support) were highly sought after.

Android, however, completely disrupted the realm, turning the tables on the major Embedded
Linux players. Rather than acquire a license for tens of thousand of dollars, embedded Linux now
became entirely free - by simply downloading the Android sources and NDK, anyone can build and
customize the system to their own needs. Android in its headless deployment now forms the basis for
many systems which don't need GUI - sensors, appliances and others, and is likely to be a major
player in the "Internet-of-Things" revolution, which promises to embed ARM and MIPS (and maybe
Intel) processors in everything but the kitchen sink.

It's possible in Android to enjoy the best of both worlds - that is, both the rich frameworks, and
a system with no UI. The system can be made to operate with no UI by setting the ro.headless
system property. This allows developers to use the frameworks for various non-UI related tasks
(such as interfacing with sensors), as well as benefit from the object orientation and other advanced
aspects of the Dalvik and ART environments.

22

---

**Page 24**

Android Internals::A Confectioner's Cookbook (Volume 1)

Pondering the Way Ahead

Prophecy is the gift of fools, but it's interesting to contemplate the next direction to be taken by
Android. The war between iOS and Android rages on, with Android quickly adopting (and, by some
claims, blatantly copying) features from iOS - and in some cases vice versa. Still, it seems rather clear
from the present landscape as to some features will very likely be included in the next Android -
Macaroon, Meringue or whatever condiment name Google will choose for it.

64-Bit compatibility

With the introduction of the iPhone 5S, Apple caught the entire mobile industry by surprise, with
the first 64-bit mobile architecture. This perplexed many, which were quick to dismiss it as useless
marketing. 64-Bit support was initially discounted because its chief advantage, address spaces larger
than 4GB, is in fact questionable in a mobile environment. Though some tablets already ship with RAM
of 2GB, 4GB are still beyond the needs of most devices. 64-bit memory access is also slightly less
efficient than 32-bit (involving more page table lookups), so many were quick to mock Apple for such a
"feeble attempt at innovating" and a useless gimmick«.

In practice, however, there's more to 64-bit than meets the eye. Though ARM 64-bit processors
still support 32-bit code, the native 64-bit (ARMv8) instruction set has been completely rewritten to be
more efficient. Add to that, the width of 64-bit registers (and the larger register set), and the
advantage quickly becomes apparent. The 64-bit architecture (along with some remarkable designs in
Apple's custom A7 chip), blew past the performance of all other mobile processors, while maintaining
an impresively low power footprint. In fact, this proved that the boasting quad and octo-cores was the
useless gimmick, as Apple's flagship processor was still a dual-core. Further, adding more cores directly
impacts power performance, so most cores are actually powered off the overwhelming majority of a
device's life time.

The move - a vertical, rather than a horizontal expansion, thus proved to be a brilliant one, and an
especially efficacious stratagem: Though requiring virtually no work in iOS other than a recompilation
of the app, porting Android to 64-bit is a lengthy process. Android's core components - notably Dalvik
and Bionic - are 32-bit optimized, and therefore need to be completely rewritten. Of all vendors, Intel
has been quickest to jump on the 64-bit wagon, since its mobile processors are already fully 64-bit
native. The various ARM vendors, however, need to adapt to the move (though Samsung was quick to
announce their "next big thing" will naturally be 64-bit). HTC's Nexus 9 was among the first 64-Bit
ARM processors (Nvidia's Tegra K1), and Qualcomm soon followed with the Snapdragon
810 (HTC One M9), and Samsung with their Exynos (in the S6). QEmu (which powers the Android
emulator) has finally been updated to support ARM64 emulation with the M Preview Release 1 SDK.

Android RunTime (ART)

Android still proves inferior to iOS in several aspects, not the least of which is power
management. This can be traced back to its Linux foundations (which are geared towards an
immobile desktop or server, where power is rarely a concern), but also due to its many layers.
While layers provide for elegant abstrations, portability and other aspects of fine design, they
are often dismal in terms of performance and power management, as they require more
processing. The main layer in Android - Dalvik - involves significant processing, and even its
many enhancements (e.g JIT compilation) still require much more work than native code would.
By comparison, iOS's runtime and frameworks are implemented in Objective-C, which is an
extension of standard C, and still very much native**.

* - One of the strongest rebukes of this move was made by none other than Qualcomm's senior VP and CMO, who claimed
"they are doing a marketing gimmick. There's zero benefit a consumer gets from that". A week later Qualcomm retracted
his comment, and he was shortly after "reassigned"29,

** - In iOS 8, Apple has made the first moves to break away from Objective-C with the introduction of Swift, a featureful

yet lightweight programming language which boasts impressive runtime performance when compiled, but also when
interpreted.

23

---

**Page 25**

Chapter |: Introduction

The Android RunTime (ART) provides an alternative. Silently introduced in KitkKat and dubbed
"experimental", ART aims to use Ahead-of-Time (AOT) compilation, to LLVM and even native code,
thus bring it on par with iOS performance. ART presently offers only small advantages in power and
performance over Dalvik (on order of 10-20%), and in some tests also falls behind it. Nonetheless,
as of Lollipop, ART is the chosen runtime, and is vital in order for Android to provide 64-bit support.

As alluded to earlier in this chapter, however, Dalvik is far from dead: Applications will still be
packaged with Dalvik bytecode (classes.dex), with ART taking over and compiling to native code
only when deployed on the device (replacing the on-device optimization stage usually carried out by
dexopt). Both Dalvik and ART are discussed in depth in Volume II).

Split-Screen

Android already has the necessary foundations to allow different activities to run in parallel to
one another on a split screen: Samsung has extended the GUI for this capability, which is also
supported in Windows 8, and with rumors abuzz for this feature to be added to the iPad in iOS 8.1,
it makes sense to see it mainstream on Android. This is a purely framework-level feature, since from
the native perspective there's no real change - the activities as processes run concurrently anyway.
This could be a major step on the road to making Android a full desktop OS replacement, as well.

Android as a desktop OS

With so many tablets vying to become a desktop replacement, why not make Android a desktop
OS? Microsoft introduced Windows 8, which took desktop Windows, and improved(?) it to support
mobile devices - tablets and phones. Android would need to make the reverse transition, bringing its
mobile support to desktops, which could then run Android apps.

Doing so is not necessarily that hard - as we discuss in Volume II, Dalvik's open source nature
makes it quite portable, and implementations for other OSes - naturally, Linux, but also Windows, OS
X and even iOS(!) exist. None of those are sponsored nor supported by Google, but with iOS and OS
X edging closer and closer still to one another, some have postulated that OS X will soon run iOS
apps (some have even go so far as to suggest Apple will make the transition to ARM on its Macs). If
that were the case, the binding between the ecosystems would become a strong differentiator in
iOS's favor, which Google will surely not ignore for long.

There are a few obstacles, however. For one, it's not trivial to support full desktop applications.
The Linux OpenOffice and most other apps are already built on top of X-Windows (and GNOME or
KDE), and thus would have to be adapted to Android. In addition, Android would have to be
extended to support mice (though arguably its InputManager already supports cursor devices), and
multiple windows (again, technically supported to an extent by the WindowManager). Last but not
least is ChromeOS, which Google is developing as its answer to Windows, in the hopes of ousting the
latter the same way Chrome usurped the lead to become the world's most popular browser.

Android and Project ARA

ARA?! is the code name for a project developed by Google with the goal of producing a fully
modular smartphone. The idea is to make all system components swappable - the CPU, display,
storage - are all replaceable, much in the same way in the PC world it's a farily simple matter to
install a new hard drive or graphics adapter. ARA is a vestige of Google's Motorola Mobility acquisition
(since sold off to Lenovo), developered by the former's Advanced Technology and Projects (ATAP)
division, which was retained by Google.

* - It's important to note that Dalvik code is still 32-bit, rather than 64-bit optimized. While Dalvik does support "wide" data
types, most operations are 32-bit. This means that, while compiling to native code does offer some benefits of the 64-bit
architecture, the code is still not as efficient as "pure" 64 bit.

24

---

**Page 26**

Android Internals::A Confectioner's Cookbook (Volume 1)

ARA makes the device, in Figure 1-6: Modular smartphones (from the Motorola blog)
T

effect, a chassis (more
accurately, an endo skeleton),
and components are separate
modules - not unlike a PC.
Electro permanent magnets
(that can be turned on/off
electronically, but do not require
power for everyday use) hold
modules in place. In theory, all
components (save for the CPU,
and possibly the display) are hot
swappable (i.e. they can be
replaced while the device is
working). Coupled with 3D
printing, this could lead to
"printable" phone designs which could be downloaded, and an array of upgradeable
modules which would render the annual full upgrades of mobile devices extinct.

As ARA is developed by Google, it's only natural that Android be the OS of choice for it.
Supporting ARA, however, will require heavy modifications in Android - at the framework level,
but even more so at the underlying Linux layers, all the way down to the kernel. Google has
partnered with Linaro for these purposes, and is investing ridiculous sums of money at
developing both the software and hardware necessary to standardize all the modules. ARA is
still in its infancy as this book goes to print, with an estimated release (initially, in Puerto Rico)
later in 2015. If successful, however, a truly modular mobile device would amount to nothing
less than a second coming of the mobile revolution - and this time, Google wants to be there
first.

Summary

This chapter explored the evolution of the Android architecture to the present day (KitKat),
with an emphasis on its low-level features. It compared and constrasted the Android
architecture with that of its parent - Linux, to show the two are in many cases not at all that far
apart, though at present not interchangeable. Next, the many derivatives of Android were
introduced, and though of different skins and appearance, they all, at their core, function as
Android does, so you should find this work applicable to them just the same. The chapter
concluded with pondering future directions for Android (L, and beyond), and the features it is
likely (or not) to support.

The next chapters explore the various aspects of Android, each in as much detail as
possible. We begin with the Android Filesystem - naturally based on that of Linux - but using
defined partitions and filesystems (some more clearly defined than others).

25

---

**Page 27**

Chapter |: Introduction

References

1. Android version History, WikiPedia: http://en.wikipedia.org/wiki/Android_ version history

2. Android Dashboards (usage statistics):
http://developer.android.com/about/dashboards/index.html

Froyo feature summary: developer.android.com/about/versions/android-2.2-highlights.html

4. Gingerbread feature summary: developer.android.com/about/versions/android-2.3-

highlights.html
5. Honeycomb feature summary: developer.android.com/about/versions/android-3.0-
highlights.html

6. SMP Primer for Android: http://developer.android.com/training/articles/smp.html

Ice Cream Sandwich feature summary: developer.android.com/about/versions/android-4.0-
highlights.html

Jellybean feature summary: developer.android.com/about/versions/jelly-bean.html
Kitkat feature summary: developer.android.com/about/versions/kitkat.htmlKitkat feature

summary

10. Lollipop feature summary: developer.android.com/about/versions/lollipop.html

11. Android version numbering convention: https://source.android.com/source/build-
numbers.html#platform-code-names-versions-api-levels-and-ndk-releases

12. A much better Android architecural diagram:

http://source.android.com/images/android_ framework _details.png

13. Dan Bornstein presenting Dalvik, Google I/O 2008: https://www.youtube.com/watch?
v=ptjedOZEXPM

14. Android NDK: http://developer.android.com/tools/sdk/ndk/index.html

15. Google Groups Bionic discussion: http://android-
platform.googlegroups.com/attach/0f8eba5ecb95c6f4/OVERVIEW. TXT eview=1&part=4

16. Android Kernel Configuration: https://source.android.com/devices/tech/kernel.html
17. Android Wear Developer Website: http://developer.android.com/training/building-

wearables.html
18. Android Auto Developer Website: http://developer.android.com/training/auto/index.html
19. Android TV Developer Website: http://developer.android.com/training/tv/index.html

20. Qualcomm reassigns exec after 64-bit criticism: http://www.cnet.com/news/after-apple-64-
bit-a7-criticism-qualcomm-exec-reassigned/

21. Project ARA official Website: http://www.projectara.com

26

---

**Page 28**

VI: The Framework Service Architecture

The previous chapter painted only a partial picture of the runtime services in Android. The

services detailed therein were all native-level processes - implemented in C/C++, and with no direct
programmatic interface from the Java layer. As such, they can be classified as services which
support the operating system itself. Applications, however, make use of an entirely different set of
services, provided by the Dalvik-level frameworks, with special interfaces. These services have a
Java language interface, and most of which run in the context of one process: system_server, and
are reachable with the help of servicemanager.

Both servicemanager and system_server were introduced throughout the previous
chapter. servicemanager in the section dealing with core services, and system_server aS a
subset of Zygote - i.e. started by zygote when the --start-system-server argument is
provided. Both, however, deserve a much more in-depth investigation, as together they provide the
support and the context of the entire Android framework service architecture - which is what this
chapter discusses.

We begin by revisiting the service manager, which provides the role of an endpoint mapper
(that is, allows service location and invocation). The services make themselves visible to clients by
registering with servicemanager, and from that point on clients may approach the
servicemanager and request a connection (or a handle) to the service. All framework services are
invoked in the same way, and this service calling pattern, is discussed next. In particular, two key
components are introduced - The Android Interface Definition Language, or AIDL, providing the
interface (or set of APIs) exported by the services, and the service utility, which allows the testing
and debugging of those interfaces from the command line.

The underlying transport for service (and, indeed, all inter-app) communication is Android is the
Binder mechanism, which is accessible to applications via /dev/binder. What looks like a simple
device node is, in fact, an elaborately designed IPC framework, which is charged with not only
dispatching messages, but also with passing around objects, descriptors, and more, as well as
providing reliability and security. This is discussed as we take a a closer look at service internals.

Lastly, we take a look at system_ server itself, which functions as the service host process,
wherein most services* are implemented as threads. We detail the startup, operation, and internals
of this important process. As for the services themselves - they're detailed in the next volume of this
work.

* - A few notable exceptions are SurfaceFlinger and the media services. Note that application (3rd
party) services run in their own process.

161

---

**Page 29**

Android Internals::A Confectioner's Cookbook (Volume 1)

Revisiting servicemanager

If you recall from the previous chapter, one of the services classified by init in the "core" class is
the servicemanager. The other key services are dependent on it, and must be restarted with it if
it crashes. Further, servicemanager is designated as critical, which means that init will agressively
attempt to restart it, or boot to recovery if it fails to do so.

The reason behind the utmost importance of the servicemanager is its function: It serves
as the locator, or directory, for all other operating system services. If any application or system
component needs to use another service, be it what may, it must first consult the
servicemanager to obtain a handle. Similarly, services cannot expect clients until they register
their presence with it. It is for this reason that, if the manager is restarted, so must all of its
dependents - after all, restarting implies the service directory must be rebuilt from scratch, and
services thus need to register. It likewise follows that, if servicemanager cannot operate, Inter-
Process Communication (IPC) cannot subsist.

The IPC model of Android is discussed later in this chapter. For the moment, however, suffice it
to say that it is provided by a dedicated kernel component - the Binder. User-mode services access
the binder for IPC via a character device node - /dev/binder, which is readily accessible
(readable/writable) to all processes. Only one user-mode process at a time, however, can request to
register as a context manager with the Binder, however, and from that point on it becomes the
focal point for all other processes - both clients, and servers. The servers must register their service
name and interface with the context manager, and the clients must consult the context manager in
order to lookup and find the service.

The servicemanager is therefore a pretty small binary, with a simple operation: a call to
binder_open obtains the /dev/binder descriptor, and a call to binder_become_context_manager
establishes its position. Thereafter, the servicemanager enters an endless binder loop, which
blocks on the descriptor, until a transaction (i.e. request from a client) occurs. This wakes process,
and calls its svcmgr_handler callback, which processes the transaction.

The service lookup must somehow be bootstrapped - in other words, the servicemanager
should be globally accessible, so that services can register with it, and clients can look them up. At
the native level, services and clients alike can call on defaultServiceManager () to get a handle
to the service manager (technically, to its interface, as a sp<IServiceManager>). The interface
(defined in IServiceManager.h) exposes a simple set of transaction request codes. Table 6-1 shows
the requests, as well as the native level calls which implement them. Note, that there is no API to
remove the service. Services are automatically removed when their proceeses die, because Binder
can detect that, and send a death notification.

Table 6-1: servicemanager requests and the programmatic methods to invoke them

Request Code API Notes
addService(name, |Used by servers to register themselves with the service
SVC_MGR_ADD SERVICE |service, manager. Servers can decide whether or not they want
allowIsolated) to allow isolated (sandboxed) processes to connect.

SVC_MGR_GET_SERVICE

checkService (name) |Get a handle to the service specified by name.
SVC_MGR_CHECK_SERVICE

Return a vector (list) of all services. Not used by the

SVC_MGR_LIST_SERVICES]listServices () framework, but used by service list
, '

162

---

**Page 30**

Chapter VI: The Framework Service Architecture

The addService functionality is considered sensitive: UID 0 or 1000 (AID_SYSTEM) can freely
register services, but other system services are restricted. Up to and including KitKat, this is done by
a hard coded allowed list, restricting registration, as shown in Table 6-2:

Table 6-2: Hardcoded service registration restrictions

AID_MEDIA media.audio_flinger, media.log, media.player, media.camera, media_audio_policy
AID_DRM drm.drmManager

AID_NFC nfc

AID_BLUETOOTH ] bluetooth

AID_RADIO radio.phone, radio.sms, radio.phonesubinfo, radio.simphonebook

AID_RADIO* phone, sms, iphonesubinfo, simphonebook

AID_MEDIA common_time.clock, common_time.config
AID_KEYSTORE __ Jandroid.security.keystore

* - These are legacy service names, deprecated by their radio.* counterparts

In Lollipop, the hard coded list is moved into the /service_contexts file of SELinux, which
provides a far more scalable way to control services - system_server.c code is simplified by a call to
check_mac_perms (), which then calls on selinux_check_access(). In this manner, service
registration and lookup can be enforced for all services, further allowing the device vendor to add
their own services, without the need to recompile any code.

Listing 6-1: The /service_contexts SELinux policy file

#line 1 "external/sepolicy/service_contexts"

accessibility u:object_r:system_server_service:s0
android.security.keystore u:object_r:keystore_service:s0
batteryproperties u:object_r:healthd_service:s0
batterypropreg u:object_r:healthd_service:s0
bluetooth u:object_r:bluetooth_service:s0
common_time.clock u:object_r:mediaserver_service:s0
common_time.config u:object_r:mediaserver_service:s0
display. qservice u:object_r:surfaceflinger service:s0
drm. drmManager u:object_r:drmserver_service:s0
inputflinger u:object_r:inputflinger_service:s0
media.audio_flinger u:object_r:mediaserver_service:s0
media.audio_policy u:object_r:mediaserver_service:s0
media.camera u:object_r:mediaserver_service:s0
media. log u:object_r:mediaserver_service:s0
media.player u:object_r:mediaserver_service:s0
media.sound_trigger_hw u:object_r:mediaserver_service:s0
nfc u:object_r:nfc_service:s0

& u:object_r:default_android_service:s0

The programmatic APIs are wrapped by the framework class
android.os.ServiceManagerNative, which is further encapsulated in
android.os.ServiceManager. Apps aren't expected to use this directly, and instead call on
Context .getSystemService () in order to look up system services, and use intents for third
party services. Either way, communication with services - both system and third party - is performed
over binder messages, with the servicemanager serving as the service directory, as shown in
Figure 6-1:

163

---

**Page 31**

Android Internals::A Confectioner's Cookbook (Volume 1)

Registering and accessing Android framework services

Figure 6-1

(" ‘auoujaainesppe

(yeu “SweU) NOLLOVSNVHL J0IAWaS Gav

|=

¥

JaZeuUBWSdIAIaS

(aweu) NOLWOVSNVYL J0IANaS 139

(awoujanasies

(awou)jaaAlasiad

1wuel|D

@apooiun ul ‘BWeU Bolas

BWPU JO yBUeT]

¢88e901d payejosi oO] ajqissaaze
eJep uoNesj0U yyeap Japulg
a0UaJajes JAaPUIg O} Ja]UIO,

Agua JX98U O} Ja]UIOd 4s] psyury

FS1[DAS

164

---

**Page 32**

Chapter VI: The Framework Service Architecture

Experiment: Using the service command to interface with service manager

Android provides the service command line utility as a simple interface for the service
manager. This simple utility also demonstrates how to use the programmatic APIs to query
services. Using service list you can display all registered services, as well as their published
interfaces (discussed later in this chapter), and using service check, see if a given service can
be contacted.

Output 6-1 shows an output of service list ona Nexus 5 Android L. Because you can
easily run this command on any device, the output is partial, highlighting only those services which
are new in L, or are not present in the emulator.

Output 6-1: Using service list onan Android L Nexus 5

root@generic# service list

Found 93 services: # Emulator shows only 87 services, 75 in KK
sip: [android.net.sip.ISipService # Not in emulato
phone: [com.android.internal.telephony.ITelephony
iphonesubinfo: [com.android.internal.telephony.IPhoneSubInfo
simphonebook: [com.android.internal.telephony.IIccPhoneBook
isms: [com.android.internal.telephony.ISms
nfc: [android.nfc.INfcAdapter ] # Not in emulato
telecomm: [com.android.internal.telecomm. ITelecommService ] #L
launcherapps: [android.content.pm.ILauncherApps
trust: [android.app.trust.ITrustManager ] #
media_router: [android.media.IMediaRouterServic
tv_input: [android.media.tv.ITvInputManager ] #
hdmi_control: [android.hardware.hdmi.IHdmiControlService] #
media_session: [android.media.session.ISessionManager ] #
print: [android.print.IPrintManage
assetatlas: [android.view.IAssetAtla
dreams: [android.service.dreams.IDreamManage

voiceinteraction: [com.android.internal.app.IVoiceInteractionManagerService]
appwidget: [com.android.internal.appwidget.IAppWidgetService]

backup: [android.app.backup.IBackupManager ]

jobscheduler: [android.app.job.IJobScheduler] # L

ethernet: [android.net.IEthernetManager ] # Not in emulat
wifiscanner: [android.net.wifi.IWifiScanner] #L

wifipasspoint: [android.net.wifi.passpoint.IWifiPasspointManager] # L
wifi: [android.net.wifi.IWifiManager ]

wifip2p: [android.net.wifi.p2p.IWifiP2pManager ]

netpolicy: [android.net.INetworkPolicyManager ]

netstats: [android.net.INetworkStatsService]

network_score: [android.net.INetworkScoreService] # L

bluetooth manager: [android.bluetooth.IBluetoothManager] # Not in emulator

display.qservice: [android.display.IQService] # owned by SF,Not in Emulator

# Use "service check" with one of above names to see if service is alive
#

root@generic# service check media.camera

Service media.camera: found

The output from the command may vary considerably between devices. Some differences are
obvious (for example, the Phone service will not be found on tablets), while others may be less so
(vendor specific services, or Android version specific).

The IBinder interface defines a dump () method, which is used by the dumpsys command
to provide diagnostics on services. When invoked without arguments, dumpsys iterates over all
services in the same manner aS service list, and dumps each in turn. In some cases,
additional arguments may be supplied, which vary with each service. Some services also expose a
"checkin" method, which can be used by dumpsys -c or --checkin.

165

---

**Page 33**

Android Internals::A Confectioner's Cookbook (Volume 1)

The Service Calling Pattern

Android's framework services are implemented in system_server threads. Applications thus
need to rely on Inter-Process Communication (IPC) in order to invoke them. This is where the
Binder, Android's properietary IPC mechanism, comes into play. Applications need to call on the
Binder in their own process to obtain an endpoint descriptor, which is then connected to the remote
service. Methods can then be invoked through IPC messages, through a pattern known as Remote
Procedure Call (RPC).

IPC? RPC?

The terms IPC and RPC are often used interchageably, though not often correctly. Because
both terms are fundamental in the context of Android services, it's worth clarifying the
difference:

e Inter Process Communication (IPC) is a blanket term for all forms of
communication between processes. These include various forms of message passing,
but also shared resources (most notably, shared memory), along with synchronization
objects (mutexes and the like), meant to ensure safety in concurrent access to shared
resources (i.e. prevent data corruption which occurs when two writers attempt to
modify the same data item, or race conditions between readers and writers).

e Remote Procedure Call (RPC) is a specific term for a method of IPC, which hides the
actual communication inside procedure (method) calls. The client calls a local method,
which in turn is responsible for transparently handling the IPC with the remote server -
which may at times be on a different machine. The method serializes its arguments into
a message, which is then transported to the server's method, where the arguments are
deserialized, acted upon, and the same occurs (in reverse) for passing the return values
of the method, if any.

Thus, any RPC mechanism is also an IPC mechanism (the former being a special case of
the latter), but not vice versa. Android's service calling pattern implements RPC, as we discuss
and detail in this section. Table 6-3 compares the RPC mechanisms used in contemporary
OSes:

6-3: Comparison of RPC mechanisms in common operating systems

Os Mechanism Scope Directory Preprocessor Transport
UN*X SunRPC Local/Remote} portmapper rpcgen UDP/TCP
OS Mach Local launchd mig Mach messages
x/iOS (Remote) (mach_init)
Android Binder Local* servicemanager aidl /dev/binder

As shown in the table, all RPC mechanisms have common denominators, specifically:
e scope: denoting whether the RPCs are used in between hosts (remote), or only on the
local host
e Directory: The server providing the lookup functionality for locating services

e Preprocessor: The tool used to generate the serialization and deserialization code for
messages

e Transport: The medium for message passing

We revisit RPC and discuss it in far more detail when dealing with Binder.

166

---

**Page 34**

Chapter VI: The Framework Service Architecture

Android developers remain blissfully oblivious to the underlying implementation of service
invocation. Instead, as most Android developers are familiar with, they are required to call on the
getSystemService() method of the Context object, which accepts the name of an Android
system service, and returns an opaque object. The object returned can then be type cast into the
specific service object, and the service methods can be invoked through it.

Figure 6-2 shows the general pattern followed by most service method calls. The figure is
somewhat simplified (for example, the system service handles are cached), but still presents the
flow. Services are registered, a priori, by the server process (commonly, system_server, or a 3rd
party process), through a call to android.os.ServiceManager. Recall this class provides a Java
interface to the service manager.

Figure 6-2: Android system service call pattern

User App

servicemanager

GET_SERVICE_THANSACTION

getService(name)

ADD_SERVICE_TRANSACTION system_server

getService(name)

addtService(name)

! addService(name,...)

getSystemService(name.)

Advantages and disadvantages

The system service architecture of Android follows a generic local client/server pattern, common
to other OSes, such as iOS. Though iOS has no Binder, it uses its own implementation of a message
passing architecture, called Mach messages. The role of servicemanager (i.e. the endpoint
matter) is assumed by i0s's launchd process, which (among other things) also handles the
traditional PID 1 roles that Android's /init does.

A disadvantage which quickly stands out in this architecture is the overhead of IPC, particularly
the need to serialize and deserialize messages, as well as the context switch required when
alternating between the processes. This disadvantage does have a noticeable performance impact.

* - Android's Binder is, by design, limited to a local scope. It's a fairly simple hack to set up a local proxy process to further
serialize and deserialize requests over a TCP or UDP socket, thus extending Binder's scope - a highly useful capability for a
Remote Access Tool (RAT).

167

---

**Page 35**

Android Internals::A Confectioner's Cookbook (Volume 1)

Given such a considerable disadvantage, it must be offset by advantages greater or equal in
magnitude - and indeed, it is: Aside from the cleaner design and separation of privileges which
follows, a client/server architecture gains security as a corollary. The client process - which is, by
definition, an untrusted user app, is entirely devoid of any permissions, and therefore relies entirely
on service calls to perform any operations. At the native level, this means that an app can be run
sandboxed, without any access to devices and datastores, if any. Indeed, this is the case in iOS
(wherein apps are "jailed"), though Android relies (for most processes) on filesystem permissions to
deny access.

The server processes are trusted, and expected to perform all security checks, ensuring the
client has the necessary permissions before agreeing to serve the request. Once again, the two arch
rivals are similar here, with iOS relying on entitlements, (embedded in the binary's code signature),
and Android on the application's Manifest file. In both cases, the permissions are declared outside of
the application's runtime scope - i.e. they can be verified when installed (or, in iOS's case, when
Apple vets the app), but cannot be modified by the App: Specifically, iOS's Entitlements are stored in
kernel space (as part of the cached code signature blob), whereas Android's permissions are
maintained by the PackageManager.

Serialization and the Android Interface Definition Language (AIDL)

In design pattern parlance, the object obtained from get SystemService serves as a Proxy:
Internally, it holds a reference to the actual service, which it obtains over a Binder call. The methods
exported by the object are, for the most part, merely stubs, which take their arguments, and
serialize them into a Binder message, referred to as a Parcel. The methods and objects serializable
in this way are specified using AIDL. AIDL isn't really a language, per se. It's essentially a derivative
of Java which is understood by the aid1 SDK utility, which is invoked in the build process when .aid|
files are encountered. The aidl automatically generates the Java source code required to serialize
any parameters into a Binder message, and extract the return value from it. The code is
"boilerplate" - i.e. it can be automatically generated from the definition files and is guaranteed to
compile cleanly. A sample .aid! file is shown in Listing 6-2:

Listing 6-2: A sample .aidi file

package com.NewAndroidBook.example; // Creates java directory structure
import com.NewAndroidBook.whatever; // Dependencies, if any

interface ISample {

// Published interface - will be shown as com.NewAndroidBook.example.ISample
// The numbers are the ones used when serializing (and using service call)

/* 1 */ void someFunc (int someArg); // no return value, integer argument
/* 2 */ boolean anotherFunc (String someArg); // returns boolean, string argument

// ... ete.. etc..

As you can see, an .aid! is somewhat similar to a header file, in that it defines methods (and
possibly objects), but not their implementation. As we explore the individual framework services
later in the book, you'll be able to see many more examples of actual .aidis from the AOSP.

The aidl tool does a marvelous job of hiding the implementation details of Android's IPC from
the developers. So great a job, in fact, that most developers remain blissfully ignorant of the role of
Binder, or its very existence. This work, however, recognizes the role of Binder, providing an
introduction to it later in this chapter, and discussing internals in Volume II.

Power users can remain equally oblivious to Binder, especially with a powerful tool like the
service utility, which enables the invocation of Android service methods right from the command
line. This is shown in the following experiment.

168

---

**Page 36**

Chapter VI: The Framework Service Architecture

Experiment: Using the service command to call services

A previous experiment demonstrated the basic usage of the service command line utility, as
a method of interfacing with the servicemanager process. The true power of service,
however, lies in its ability to call the services themselves.

Calling a service is a simple enough matter - using service call, and specifying the
service name and method number: Internally, methods are assigned numbers in order of their
appearance in the service's .aidl file. Depending on the method, optional arguments may be
supplied. The service utility supports two types of arguments: i32, which are integer values,
and sié, which are used for unicode strings. In practice, however, integers can be used for any
32-bit value (e.g. float), and strings - being unicode - can be used to serialize any object.

Any service retrieved by service list (Output 6-1) with an interface (specified in
brackets) can be called on in this manner. Each interface has a corresponding .aidl file in the
AOSP, wherein its methods and their arguments are clearly defined. Once you have the
definitions, you can invoke any method of your choice, by figuring out its call number and passing
the appropriate arguments. A few of the interesting ones are shown in Table 6-4:

Table 6-4: service call commands

service call... Interface Method Action
phone 2 si6 "foo" call(String callingPackage, |Place a call to the specified

$16 "555-1234" T Telephony String number); number.
statusbar 1 expandNotificationsPanel() | Brings up notifications
statusbar 9 IStatusBarService | expandSettingsPanel() Brings up settings
statusbar 2 collapsePanels() Hides all panels
dream 1 IDreamManager dream() Screensaver (if configured)
bower i S 443) IPowerManager isScreenOn() Returns 0 if screen is off, else 1

Invoking calls in this way will return a result in a Parcel (the Binder term for a message). Each
parcel contains, at a minimum, a 32-bit return value (0x00000000 indicating success, otherwise
some error value, commonly oxfffffffE or OxffFEEEb6 ("not a data message") if a call
number is outside the defined range). Depending on the AIDL definition, what follows is either an
integer value (i32), or a length specification, followed by an opaque object (usually, but not
necessarily, a string). Because service, like Binder, has no idea of what the opqaue object is, it
will display the result in a manner not unlike the od command, with a hex dump of the message
contents, alongside an ASCII dump of it.

169

---

**Page 37**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Using the service command to call services (cont.)

Only services with a published interface (specified in [brackets]) can be invoked. Note, not all
services will blindly lend themselves to this type of invocation: Depending on the security policy,
which is implemented differently by individual services, your service call request may be denied. If
that is the case, the output of service cali will contain a unicode error message, like so:

Output 6-2: Error messages returned from service call

shell@htc_m8wl:/ $ service call phone 13

Result: Parcel (
0x00000000: fffffFFF 00000050 0065004e 00740069
0x00000010: 00650068 00200072 00730075 00720065
0x00000020: 00320020 00300030 00200030 006£006e
0x00000030: 00200072 00750063 00720072 006e0065
0x00000040: 00200074 00720070 0063006f 00730065
0x00000050: 00200073 00610068 00200073 006e0061
0x00000060: 00720064 0069006f 002e0064 00650070
0x00000070: 006d0072 00730069 00690073 006e006f
0x00000080: 004d002e 0044004fF 00460049 005£f0059
0x00000090: 00480050 004e004f 005f0045 00540053
0x000000a0: 00540041 002e0045 00000000

ocOororvuaonrs
HHUAaAHDROS Se
nKoOUROOE OE

| pOpBpNUSBORGE

ZonrowrR Go

Once you get past permissions, however, (for example, by running as root), the possibilities
of using service call in this manner are nearly endless, spanning all the features and
capabilities of the Android frameworks. As we cover the framework services in this work one by
one, we'll be showing their respective AIDL definitions, and number the calls accordingly.

170

---

**Page 38**

Chapter VI: The Framework Service Architecture

The Binder

The discussion so far has mentioned the Binder several times, but kept it a very high level
overview. Indeed, at a high level, suffice it to consider the Binder as a special type of a file
descriptor, which - through a dedicated kernel driver - is connected to the service. This is also how
Linux sees it, when the process is viewed through the /proc/pid/fd directory. Virtually every process
in the system (With the exception of a few native processes) opens a handle to /dev/binder.

Much of Binder's inner workings, however, are shrouded in darkness - probably because, for
most developers, ignorance is bliss. For those who want to know the details, there is, after all,
always the source. For the scope of this work, however, it's beneficial to elucidate some of these
dark corners and provide a closer view of Binder, explaining its functionality without going into
the (not so well documented) source.

A little history

The Android Binder mechanism traces its root back to the Binder of another mobile operating
system, BeOS. Binder served as the underlying support interconnecting BeOS's rich set of
frameworks. Once heralded as the "next generation operating system", BeOS never gained much
traction save for a few fans, and was eventually acquired by Palm. If the name doesn't ring a bell,
that's fine - Palm Pilots were all the rage back at the end of the last millenium, catapulting 3COM to
great heights before Palm was split off and spiraled back to earth. Palm was eventually acquired by
HP, and its OS served as the basis for "WebOS", another venture that fell far short of its promise.

Binder, however, survived. Besides being ported to PalmOS (and integrated into their Cobalt
architecture), it was also ported to other operating systems - including, of course, Linux. The Linux
port was open sourced (at http://openbinder.org/, and though the website seems to have died
since, some mirrors! survived). The original developers left Palm to join Android, and brought Binder
with them. Chief amongst them was Dianne Hackborn, a well renowned developer and still one of
the major figures driving Android today. An interview she gave to OSNews? back in 2006< explained
the fundamentals of OpenBinder.

Android's implementation of Binder is more specific than OpenBinder, and - just like as originally
intended in BeOS - serves as the fulcrum for all of its frameworks.

So, what, exactly, is Binder?

Binder is a Remote Procedure Call mechanism, allowing applications to communicate
programmatically, but without having to worry about how to send and receive messages. From the
application's perspective - server or client - all it needs to do is either call a method (client) or
provide a method (service). When the client calls the method, the corresponding method is
magically invoked in the service, with all the "details" handled transparently by Binder. These
"minutiae" include:

e Locating the service process: In most cases, the client and the service are two different
processes (system_server notwithstanding). The Binder needs to locate the service
process for the client, so as to be able to deliver the message. This "location service" (also
known as "endpoint mapping") is technically handled by servicemanager, as explained
previously, but the servicemanager is only responsible for maintaing the service directory,
mapping an interface name to a Binder handle. The "handle" is an opaque identifier, which
was given to the servicemanager by Binder, and which only Binder knows the "true"
meaning of - that is, the underlying PID wherein the service is located.

e Delivering the message: As discussed previously, AIDL is used to generate the code which
takes the parameters of the called method and serializes them (i.e. packs them into a
structure in memory), or deserializes them (unpacks the structure back to individual
parameters). The passing of the serialized structure from one process to another, however, is
handled by Binder itself. Clients call the BINDER_WRITE READ ioctl (2), which sends the
message over Binder, and blocks until a reply is returned (hence, the code - first write, then
read).

171

---

**Page 39**

Android Internals::A Confectioner's Cookbook (Volume 1)

e Delivering objects: Binder can be used to pass around objects - the service handles
mentioned previously are one such type of an object, but so are file descriptors (just like
UNIX Domain sockets). Passing around descriptors is an especially important feature, as it
allows a trusted process (such as system_server) to natively open a device or socket for
an untrusted process (such as a user app) - assuming the untrusted process has the required
permission (as specified in the App's manifest).

e Supporting credentials: Inter process communication naturally has significant security
aspects. A recipient of a message has to be able to verify the identity of the sender, so as not
to be tricked into compromising overall system security. Binder is aware of its users’
credentials - PID and UID - and securely embeds them in messages, so peers can operate
with a reasonable level of security.

Using Binder

Binder is used in all applications, whether or not the developers themselves realize it. The code
involved in binder operates on no less than three levels, as shown in Figure 6-3:

Figure 6-3: Message flow between client and server using Binder

Java Code

Native Code

Kernel Level

HS Android frameworks

[ libbinder.so
a Kernel module

In an effort to be true to the power user's view adopted in this work, Figure 6-3 is as far as we
go - for now. More detail on the various levels - from the Java objects, through AIDL, native, and
kernel - can be found in Volume II.

172

---

**Page 40**

Chapter VI: The Framework Service Architecture

Tracing Binder

The /dev/binder connection multiplexes any number of service connections over the same file
descriptor. This means that a process will hold that descriptor irrespective of whether it is connected
to one service, or to many. Indeed, a process can hold this descriptor and not be connected (yet) to
any services at all.

It follows, then, that there's no simple way to see exactly which services a given handle is
connected to. If the Binder debug functionality is enabled through the Linux debugfs filesystem
(/sys/kernel/debug/binder), however, you can use the bindump tool (on the book's companion
website) to figure out who's connected to what, as shown in the following experiment:

Experiment: Using the bindump tool to view open binder handles

The bindump tool, which you can find on the Book's companion website is nothing more than
a simple derivative of the service command, which obtains a handle to the system service of
choice (as does service check), and then inspects its own entry in the
/sys/kernel/debug/binder/proc directory. Each process using binder has a pseudo-file containing
various statistics, and the node entries contained therein reveal the PIDs connected on the other
end. Because all the binder debug data is world readable, you can run this tool on unrooted
devices as well.

Qutput 6-3: Revealing binder endpoints using the bindump utility

Service: wallpaper node ref: 2034

User: PID 1377 com.htc. launcher

User: PID 1194 com.android.systemui
Owner: PID 1008 system_server

User: PID 368 /system/bin/servicemanager

shell@htc_m8wl:/ $ /data/local/tmp/bindump owner batterypropreg
Service: batterypropreg node ref: 105785
Owner: PID 8153 /sbin/healthd

The book's companion website also provides a special version of st race (), the Linux system
call tracing tool, with augmented functionality that includes parsing of Binder messages (i.e.
deciphering toct1 (2) codes and payloads).

173

---

**Page 41**

Android Internals::A Confectioner's Cookbook (Volume 1)

system_server

Android devices have dozens of services, and along with vendor and user-installed apps, this
number can exceed one hundred. Fortunately, the vast majority of framework services are simple
enough that they do not require their own process, and can instead run as threads. These threads,
however, need a host process to run in - and that is exactly what system_server provides.

Similar to Windows' svchost.exe, the system_server provides nothing more than a shell - a
container process. The two can also be compared in the sense that svchost.exe loads services
through dynamically linked libraries (DLLs), whereas system_server loads Java classes. In
Android, however, this is even more important a function: Though the Dalvik VM is optimized for
sharing, running services alongside one another in the same VM provides an even greater savings in
resources. This does not come without a bit of risk, however, as a misbehaving service can thus
affect its siblings. For the most part, though, this isn't much of a concern, as only Android's system
services, and not those of the vendor or additional apps, are allowed to run inside system_server.

The system_server is not a native app: It is implemented mostly in Java, with some JNI calls
in places where it must start native services. The services it loads are similarly implemented in Java,
though a great deal of them also rely on JNI to escape the virtual machine and interact with
hardware components. Zygote automatically starts the system_server when it itself is started by the
/init.rc (q.v. Figure 5-22) with the --start-system-server Switch. The switch makes Zygote
invoke startSystemServer (), in which are hardcoded the arguments - capabilities, group
memberships (--setgroups), the "nice name" (system_server), and the class to load -
com.android.server.SystemServer. The system_server does not execute with root
privileges, but comes pretty close - uid:gid of system: system, enhanced capabilities, and a host
of secondary group memberships. The security perspective of system_server - GIDs and
capabilties - is shown in Chapter 8.

Startup and Flow

For such an important fulcrum of the entire system, system_server has a rather simple flow.
Once it has forked off from Zygote, the child process drops its privileges, and toggles the capabilities
as discussed above. It then proceeds to load the class, whose main() performs basic initialization
(notably lifting its VM limits and loading the 1ibandroid_servers.so to perform JNI component
initialization), before instantiating the framework services. Once all services have been created (and
their corresponding threads spun), with nothing else to do the main thread enters a looper, to loop
(hopefully) endlessly (unless the system is shut down). The high level flow is shown in Figure 6-4,
on the next page.

There are numerous system services to start, however, and system_server needs to
instantiate them one by one. Android L takes great steps in refactoring this flow. Even though much
work remains, the flow is significantly simplified from previous version by grouping services of
similar classification. There are currently three "classes":

e Bootstrap services: These include the Installer, ActivityManagerService,
PowerManagerService, DisplayManagerService, PackageManagerService and
UserManagerService. Additionally, a check is performed if the device's /data partition is
encrypted or in the process of encryption - which affects startup by starting only apps
designated as "core apps".

e Core services: These include the LightsService, BatteryService,
UsageStatsService, and the WebViewUpdateService. The last is a new service in L
which periodically checks the browser component for any updates.

e "Other" services: basically, everything else. There are dozens of services in this class
(which the source admits is "a miscellaneous grab bag of stuff that has yet to be refactored
and organized").

174

---

**Page 42**

Chapter VI: The Framework Service Architecture

Figure 6-4: The flow of system server

Ensure device time is set to the epoch (1970)

If profile integration is enabled, start sampling system_server once per hour

Ensure maximum efficiency by toggling virtual memory parameters

Verify ro.build.fingerprint exists, we have a user, and Binder calls get priority

Set up main thread so it can eventually become the looper thread

Use JNIto load libandroid_servers.so and invoke its native initializers

Call on ActivityThread to create the system context

Starts com.android.system.ServiceManager, which manages java services

Start bootstrap, core and other services, or die trying (i.e. Throw exception)

Enter looper and loop indefinitely (will throw exception if looper ever exits)

Not all the services are visible to applications: Some, like the Installer are internal, and thus
invisible both to apps as well as service list. We discuss all the services - internal and app
facing - one by one in the next chapters.

Once the services are started, SystemServer has nothing more to do in its main thread. The
thread therefore enters its looper, which hopefully loops indefinitely. We say "hopefully", since the
looper is not expected to exit, and will throw a runtime exception if it does. Internally, the loop
blocks, polling its file descriptors (and in particular, its Binder handle) for incoming messages. When
messages arrive, they are dispatched to their respective targets.

175

---

**Page 43**

Android Internals::A Confectioner's Cookbook (Volume 1)

Modifying startup behavior

The flow of system_server and the classes of services it starts can be modified by setting
certain system properties.

A key parameter is the ro. factorytest system property, which defines whether or not the
device is configured for a "factory test" mode, affecting the startup of SystemServer according to
the following values:

Table 6-5: Factory test values and their impact on startup

value #define Implies
0 (default) | FACTORY_TEST_NONE Normal startup.
1 FACTORY_TEST_LOW_LEVEL | No bluetooth, input, accessibility, lock settings
2 FACTORY_TEST_HIGH_LEVEL| Uid 0 for factory test applications

Another important parameter is the ro.headless system property, which - if set - disables the
WallPaper service, and the System UI services. The config family of properties can also be used to
selectively disable subsystems, as shown in Table 6-6:

Table 6-6: config properties affecting system services

config Property Disables
disable_storage MountService
disable_media AudioService,WiredAccessoryManager, CommonTimeManagementService
disable_bluetooth BluetoothManagerService
disable_telephony Unused
disable_location LocationManagerService, CountryDetectorService
disable_systemui StatusBarManagerService

UpdateLockService, LockSettingsService, TextServicesManager,

disable_noncore SearchManagerService, WallpaperManagerService, DockObserver, UsbService

NetworkStatsService, NetworkPolicyManagerService,WifiP2pService,
disable_network WifiService, ConnectivityService,
NsdService, NetworkTimeUpdateService,CertBlacklister

Thanks to the Linux /proc filesystem, you can examine system_server and its many threads.
Looking at its file descriptors is somewhat futile - it's impossible to tell which descriptors belong to
which thread - and most of them are sockets and pipes anyways. Enumerating the threads,
however, can be useful. This is shown in the following experiment.

176

---

**Page 44**

Chapter VI: The Framework Service Architecture

Experiment: Unraveling the threads of system_server

Dalvik's thread objects may be named when created. Naming a thread calls the underlying prct1 (2)
system call - a little known but highly useful API which allows the renaming of threads and processes at the
kernel level. The name is then visible through the /proc filesystem in the status proc entry of the thread. The
method is not perfect, as it allows for only 16 characters in a name - but it sure beats rummaging through
random thread identifiers, trying to figure out which does what.

Using a basic script (which even Android's limited shell supports) you can easily enumerate the threads,
and get their individual names (this works on any process, so as long as the for iterates over its task/
subdirectory, which contains a directory entry for each thread). Binder threads and thread pools are omitted

from this output:
Output 6-4: Iterating through threads

root@flounder:/proc/507/task # for t in *; do echo Thread St “grep Name: St/status ; done
507: Name: system_server The main thread (same as PID)
512: Name: Heap thread poo L: ART Heap thread pool
514: Name: Signal Catcher Dalvik signal catcher
515: Name: ReferenceQueueD Dalvik Reference Queue Daemon
516: Name: FinalizerDaemon Dalvik object finalizer
517: Name: FinalizerWatchd Dalvik finalizer watchdog
518: Name: HeapTrimmerDaem L: ART Heap Trimmer Daemon
519: Name: GCDaemon Garbage Collector (L: "GCDaemon", for ART)
524: Name: SensorService
525: Name: SensorEventAckR
526: Name: android.bg
527: Name: ActivityManager
529: Name: FileObserver FileObserver$Thread
530: Name: android.fg
: Name: android.ui
: Name: android.io
: Name: android.display
: Name: CpuTracker
: Name: PowerManagerSer
: Name: BatteryStats_wa
: Name: PackageManager
: Name: PackageInstalle
: Name: AlarmManager
: Name: InputDispatcher
: Name: InputReader
: Name: MountService
: Name: VoldConnector
: Name: NetdConnector
: Name: NetworkStats
: Name: NetworkPolicy
: Name: WifiP2pService
: Name: WifiStateMachin
: Name: WifiService
: Name: ConnectivitySer Created by ConnectivityManager
: Name: NsdService Neighbor Services Discovery (State Machine Thread)
: Name: mDnsConnector Created by NsdService
: Name: ranker Created by NotificationManagerService
: Name: AudioService Created by AudioServiceSAudioSystemThread
: Name: UEventObserver Kernel uevent observer (shared by many services)
: Name: backup Created by BackupManagerService
: Name: WifiWatchdogSta
: Name: WifiManager
: Name: WifiScanningSer
: Name: WifiRttService
: Name: EthernetService
: Name: LazyTaskWriterT ActivityManager's TaskPersister
: Name: UsbService host
: Name: watchdog
: Name: SoundPool AudioService$SoundPoolListenerThread
: Name: SoundPoolThread AudioService$SoundPoolListenerThread
: Name: NetworkTimeUpda NetworkTimeUpdateService's HandlerThread
: Name: IPC Thread
1009: Name: WifiMonitor
1507: Name: SyncHandler-0
1513: Name: UsbDebuggingMan

Sh Se SR SR SR SR SRO

Created by ActivityManager
Created by PowerManagerService

Created by
PackageManage

Created AlarmManagerService
Started InputManager
Started InputManager
Created MountService
Created MountService
Created ConnectivityManager

Se SR SE SR SR SR SR RR SR

TIDs aren't normally predictable, but a large part of system_server's are started incrementally, and so looking at
the IDs can give you a sense as to the system's framework startup.

177

---

**Page 45**

Android Internals::A Confectioner's Cookbook (Volume 1)

Summary

This chapter discussed the Android framework service architecture, explaining the underlying
mechanisms of Inter Process Communication (IPC) through Remote Procedure Call (RPC) in Android,
focusing on the role of the servicemanager and the service utility. It then focused on the
system_server process, which serves as a host to Android's myriad frameworks, all implemented
in Java.

This naturally begs much more discussion - specifically, of the dozens of services, and of Binder
- the transport that facilitates RPC. This discussion, however, is left for Volume II.

Files discussed in this chapter

Component File Contains
. f/native/cmds/servicemanager/service_manager.c Body of service manager
ServiceManager - - ; ; ;
frameworks/native/cmds/servicemanager/binder.[ch] Binder interface
SystemServer f/b/services/java/com/android/server/SystemServer.java}] The systemServer class
References

1. OpenBinder documentation (mirror):
http://www. angryredplanet.com/~hackbod/openbinder/docs/html

2. OSNews, Interview with Dianne Hackborn: http://www.osnews.com/story/13674/

178

---

**Page 46**

VII: Android Through a Linux Lens

Android developers are accustomed to thinking about their applications in terms of the Android
lifecycles described in the previous chapter. From the Linux perspective, however, Android
applications are Linux processes, and aren't much different from any other process on the system.

This chapter puts that very perspective in focus. We first discuss the facilities Linux provides for
process monitoring and tracing, through the /proc filesystem, which was touched on briefly in
Chapter 2, but is now explored in the detail it deserves. We discuss the per-process and per-thread
entries in /proc/pid which allow you to poll for real-time, on-the-fly statistics. First, we discuss the
symbolic links that report working directories. We next focus on the highly useful fd/ and fdinfo/
subdirectories, which provides accurate representations of open file descriptors. Next up is the
status entry, which gives a high level view of the process - and in particular, thread state and virtual

memory.

Virtual memory is an important metric for diagnosing performance, so the next section focuses
on the basics of user memory management, going into theoretical concepts, but also presenting the
smaps proc entry, and two tools - procrank and librank - which you can use to get accurate memory
statistics. We then explain the dreaded Out-Of-Memory condition, the bane of Android's application
lifecycle, forcing the app to live in the shadow of ever-looming, and very unpredictable death.

Lastly, we explain system calls, showing the toolbox ps tool, the proc entries of wchan and
syscall, and the all-powerful strace tool, which you can use for active tracing.

The chapter relies heavily on concepts from operating system theory, and is full of hands-on
experiments meant to further elucidate these concepts, which are far from trivial. The methods and
experiments shown in this chapter are all based on Linux kernel features, which makes them just as
applicable on a Linux system, as they are in Android - so you might consider referring to this chapter
for Linux Debugging tips, a subject on which there is a surprising dearth of books on.

179

---

**Page 47**

Chapter VIII: Security

The /proc filesystem was touched on in Chapter 2. The touch was hardly a graze, however, as it
has not begun to scratch the surface of this extremely important filesystem. In particular, the per-
process (and thread) directories in /proc, with their plethora of real-time diagnostic information
about the inner workings of applications.

To understand the per process directories, think of a process as in object-oriented terms: A
process can be thought of as an instance of a process class, all instances of which have the same
properties - though naturally property values may differ. The pseudo-files in the per-process
directory simply show you the values of the properties, and - in some cases, if they are writable -
allow you to modify these properties.

Output 7-1 shows the entries the Android shell would see in its own directory (using $$ as the
process ID of the current shell - note we don't use /proc/self, because 1s would see itself!). The cut
filter is optional, and is used only to improve readability.

Output 7-1: Annotated per-process entries in L (3.10 kernel).

shell@flounder: /data$ 1s -1 /proc/$$ | cut -cl-10,55-
dr-xr-xr-x attr # Attr

auxv ELF AUXilliary Vectors, in binary form

cgroup Control Group membership of process

clear_refs Clear page referenced bits in smaps
-Y--r-- cmdline Command line (argv[]), NUL separated
16-byte argv[0]
Process current working directory, as symlink
Environment (as per set or getenv()), NUL separated
Full path of executable, as symlink,
Directory containing open file descriptors, as symlinks
Directory containing metadata on open file descriptors
Process hard/soft limits, as per ulimit or setrlimit (2)
Process address space memory map
Process virtual memory, as a pseudo-file
Mounted file systems, as process sees them (mount namespace)
Mounted file systems, slightly different format
Mounted file systems, slightly different format
Network statistics of process network namespace
Namespaces of this process, as symlinks (commonly, mnt)
Out-Of-Memory (old) score adjustment. Used by ActivityManager
Out-Of-Memory score. Determines process killability on OOM
Out-Of-Memory (new) socre adjustment. Used by ActivityManager
Page map of process
OS Personality. Commonly, this is 0000000 (Linux)
Process root directory. Always symlinks to /, unless chroot (2)e
CFS statistics for this proecess, in human-readable form
More CFS statistics for this process
q.v maps, but with more detailed information per memory region
kernel stack of process (technically, main thread)
Statistics (from task_struct), in machine-readable form
More statistics, in machine-readable form
Statistics (from task_struct), in human-readable form
Current system call and arguments
Subdirectory containing entries for process threads
Wait Channel in kernel

-rw-r--r-- comm

lrwxrwxrwx cwd -> /data
-Y-------- environ

lrwxrwxrwx e? /system/bin/sh

-Y--4--41--
-Y--Y--4Y--

-r--r--r-- mountinfo
-Y--Yr--r-- mounts
mountstats
dr-xr-xr-x net
dr-x--x--x ns
-Yw-r--r-- oom_adj
-Y--Y--Yr-- oom_score
-Yw-r--r-- oom_score_adj
-r--Yr--r-- pagemap
-r--r--r-- personality
lrwxrwxrwx root -> /
-rw-r--r-- sched
-r--r--r-- schedstat
smaps
stack
-r--r--r-- stat
-r--r--r-- statm
-r--r--r-- status
-r--r--r-- syscall
dr-xr-xr-x task
-r--r--r-- wchan

SHOE HEHEHE HEHEHE HEHEHE HE HEHEHE HEHEHE HEHEHE HH HEHEHE HE

Remember - none of these are actually files. This means two things:
e The exact listing of the file may change, according to your kernel version. In general, the

newer the kernel, the more likely you are to have more pseudofiles, though support for some
of them may be disabled when compiling the kernel.

225

---

**Page 48**

e The files aren't really there, until you ask for them: which means that every time you
display the files, you're likely to get different content. When using 1s, the kernel doesn't
even bother reporting file sizes, which is why (if you try the above command without the cut
filter, all file sizes are shown as 0.

The last point is a very important one to consider: Because the files are purely virtual, there is
no overhead in maintaining the /proc entries - the kernel maintains all these statistics anyway during
normal operation. All it takes is "faking" the existence of these files, and - when the user asks for
any - collecting the statistics in real time, and providing them in pseudo-file form. This makes the
/proc filesystem an extremely powerful mechanism for system and process tracing, provided the
method used is that of polling.

Tracing by polling means that the tracing program or script has to keep on explicitly asking for
specific /proc entries periodically, because /proc entries do not support on-change callbacks (at least,
not yet). This does have certain disadvantages - if the polling granularity is too coarse, you may end
up missing the exact event you were trying to intercept. But the advantage - zero overhead - clearly
outweighs the disadvantage. The human-readability and ease of parsing of the pseudofiles is
another clear advantage, as we demonstrate in this chapter.

Because kernels change so frequently, this unfortunately has the side effect of leaving the
documentation (proc (5) on Linux systems with man installed) somewhat outdated, and not all
these are properly documented. We next turn our attention to some of the more important of these
pseudo-files, which you can readily use when profiling or debugging the system.

The symlinks: cwd, exe, root

Looking at output 7-1, three entries immediately stand out - those of cwd, exe and root. The
reason they are different is because they are shown as symbolic links, whereas other entries are
shown as pseudo-files.

The rationale behind displaying these entries as symbolic links is readability. All three entries
point to files or directories, and by using symbolic links, it makes it easier for the user to apply a file
operation (e.g. cat (1), 1s (1)) on the target of the link (which most commands follow
automatically), rather than have to first display the contents of a pseudo-file, then embed the output
into the next command.

The three entries give you the most important high-level statistics for the process, namely:

e cwd - which displays the current working directory. In output 7-1, you could see from the
prompt that the shell's present working directory is /data - and that is exactly what the cwd
link is pointing to. A fun experiment is to cd to any directory of your choice, then repeat the
ls -1 /proc/$$/cwd. You will see that you can run, but youcan't hide - Any time you use
the query the cwd entry, the kernel retrieves the working directory at that moment, which
means you will always get the right directory.

e exe - which displays the full path to the executable used to start this process (that is, the
one loaded by the execve (2) system call. This is useful because many processes can
change their name, as displayed in ps during their lifetime, but they cannot change this
entry.

e root - which displays the root directory. Normally, this will be the real root directory - (/). If
an application is chroot (2) ed, that is, confined to a subdirectory which is defined as its
new root, this will be clearly visible from this entry.

The cwd and root entries are used by tools such as fuser and Isof, which find open files and
directories by patname (fuser) or by process (Isof). Knowing this, it becomes a simple matter to
implement both these utilities as shell scripts, which could become quite useful on systems which do
not have these tools pre-installed. The following experiment shows how a similar shell script trick
can be used with the seemingly less useful exe entry.

181

---

**Page 49**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Determining the 32/64-bitness of Android apps

At first glance, an entry such as exe seems somewhat useless - after all, in most cases the
executable name isn't really expected to change during the process lifetime.. or is it?

It turns out, that's not always the case. A good example in Android are the various Dalvik
apps, spawns of Zygote, all changing their name to that of the loaded class they are executing.
This is done by changing the value of argv[0], using the prct1(PR_SET NAME. .) system call.
The real name of all these apps is still /system/bin/app_process, which is the "true" instance of the
VM which loaded them. In L this is even more useful, because 32-bit apps will be clearly visible as
app_process32, whereas 64-bit ones will be app_process64. The following example shows how you
can use that to your advantage in a shell script:

Output 7-2: Using the exe proc entry to figure out 32/64-bitness of an app

root@flounder:/# ed proc; for p in [0-9]*; do

> if 1s -1 $p/exe | grep app process32 > /dev/null; then
> echo “cat $p/cmdline™ \(PID $p\) is a 32-bit app

> £i

> if ls -1 $p/exe | grep app process64 > /dev/null; then
> echo “cat $p/cmdline™ \(PID $p\) is a 64-bit app

gle.process.location ( 10446) isa bit app
e.android.inputmethod.latin (PID 10702) is a 64-bit app

google.android.apps.maps (PID 14610) is a 32-bit app
google.android.talk (PID 15219) is a 32-bit app
zygote64 (PID 211) 64-bit app
zygote (PID 212) is a 32-bit
s em_ser (PID 511) is
com. is a 64-bit app
com.android.server.telecom (PID 930) is a 64-bit app
com. android.pho 988) is a 64-bit app

To understand the script better, note the pattern used:

1. cd to the /proc directory: Because everything starts here.

2. Iterate over [0-91* entries: The root of /proc contains additional files, alongside the per-
process entries. We want just the per-process directories, so we isolate only those entries
beginning with a digit. This will run a loop with sp set to the PID iterator.

3. Perform check by looking at the exe /proc entry: Note the use of grep, with output
discarded (> /dev/nul1). We're only interested in whether or not there was output -

grep's implicit return value, which is what the if will branch by. Because there are
actually three cases here (app _process32, app_processé64 or neither), we don't use
and if/else construct, but two separate if statements.

4. Print out the user-facing output:: Using cmdline, taking advantage of its NUL-
separation, when employing cat (1), only argv[0] is printed. This is better than the comm
entry, since the latter is truncated at 16-bytes. Note also the use of $p - our iterator, which
holds the PID (which shows the initial cd (1) was like Chekhov's Gun).

At first glance, the idea of running a script inline might deter some readers. That's
understandable, especially when considering the rigid syntax of shell scripting (which is why this is
an experiment - you're urged to try this at least once for yourself!). Remember, however, that
every inline script like that can easily be put into a file, chmod (2) ed +x - thereby becoming a new
tool for you to add to your arsenal. The exact same pattern - iterating and grep (1) ping - albeit
with different /proc entries - can be adapted to create custom, reusable tools, which will work
correctly both on Android and Linux systems.

182

---

**Page 50**

Chapter VII: Through a Linux Lens

fd

A process performs all of its I/O through file descriptors. The files, pipes and sockets opened
- irrespective of language, Java C or other, all map to numbered file descriptors, with three default
ones - standard input (stdin, stdout and standard error (stderr) - numbered 0, 1 and 2,
respectively. When a process opens or creates a file (or socket, pipe, etc), the created object is
linked to the next available descriptor. What appears to the process as a number is, in fact, a handle
to an opaque object, that only has true meaning in the kernel, wherein that handle is deciphered as
an index to an array of objects.

It is therefore of the utmost importance to be able to figure out which descriptors a process is
using in real time. There are quite a few tools for that - most notably, 1sof (list open files), which
dumps open files per process along with other mappings. Rather than rely on 1sof, however (which
may or may not be present in a given distribution), it often makes sense to get the information
straight from the horse's mouth - that is, from /proc/pid/fd.

The fd/ subdirectory follows the same symlink convention as the cwd, exe and root entries
described in the previous section. This makes it extremely useful to just 1s -1 a given PID's fd/
directory in order to figure out which files are in use. So useful, in fact, that this work demonstrated
the technique several times by now in previous chapters. It couldn't be simpler, but be aware that
listing descriptors does require root privileges if you are not the owner of the process (and, by
corollary, the /proc/pid/fd directory):

Output 7-3: Showing the file descriptors of a process (Zygote) through /proc/pid/fd:

root ( d :19 0 > /dev/null

root )4 :19 > /dev/null

root 01-04 :19 10 : [11955]
root d :19 ¢ : [6639]
root ( :19 2 -> /de larm
root 04 719 > socket: [11986]
root 4 219 ev/null

root ( Ms 0:19 t: [10409]
root 04 :19 sys/kernel/deb
root 4

root )

root 4 :1s <et: [11323]

root 0 4 0:19 8 > em/framework/framework-res.apk

root 5 = ( 04 :19 9 -> v/__propert

For regular files, this works perfectly. The convention isn't as useful, however, when it gets to
sockets. Since sockets have no filesystem representation (some UN*X sockets notwithstanding),
there is nothing to symlink to. It would be trivial to add a fake symlink, which would contain a string
of the IP or domain socket in question, but at the time of writing the Linux kernel opts instead to
take the path of least resistance, and simply spit out the inode number associated with the socket.
You can see the socket numbers above, for descriptors 7, 10, 11 and 13. But where do these
sockets connect to?

Fortunately, there are other pseudofiles in procfs which will resolve this data for you. The
following experiment shows how to figure out sockets - both UN*X and IP:

183

---

**Page 51**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Resolving inodes to socket names through /proc/net

It's always possible to "cheat" and use a tool like 1sof (1) (but not the toolbox tool) to
automatically resolve all descriptors, including sockets, for you. But with a little bit more
knowledge of Linux procfs files, it's not that hard to do so on your own. The sockets in Linux and
Android are usually one of the following types”:

e UN*X domain sockets: Used for local only communication. Some of these sockets are
named, i.e. they have a filesystem representation. In practice, these are not really files -
domain sockets are in-memory kernel constructs, and the filename is used to ensure
system-wide uniqueness. In Android these sockets are located in /dev/socket, with an
additional type of sockets using "@" naming conventions, which do not appear on the
filesystem. Other sockets may remain unnamed. The kernel keeps the domain socket
statistics in /proc/net/unix

e IP based sockets: Over IPv4 and/or IPv6. Linux (and Android) differentiates between the
two address families, and further differentiates by protocol type - udp or tcp. As a
consequence, there are thus no less than four files to consult - tcp6, udp6, tcp and udp.

e Netlink sockets: Used as an efficient kernel-user space notification mechanism. These are
unique to Linux, and are also favored because of their multicast capabilities - i.e. it is
possible to share a socket between members of a group, sending messages to all of them
at once. Statistics are kept at /proc/net/netlink.

For IP-based sockets, a simple method is to look for the inode number in the various
/proc/net™” statistics files. Since there are four files, it's quicker to do so by using grep (1), as
shown in the following output:

Output 7-4: Figuring out IP sockets from /proc/net

shell@flounder:/ $ grep 47 /proc/net/*

/proc/net/tcpé: i) OC FFFFO(

Tools such aS busybox netstat Or busybox lsof (but not those of toolbox can
parse the output - but if you do it manually, all it takes is a bit of hex-juggling: The format of
the lines is:

##: Loc_v6/v4:Port Rem_v6/v4 state .. inode# .. pname pid comm

which gives you the details you need.

Mappings for UN*X domain sockets are unfortunately not always this easy. Sometimes using
grep will yield the socket name from /proc/net/unix, but often times the socket is unnamed, which
makes it difficult to figure out which peer is connected to it. In some cases, it's possible to recover
the other end by trying one number lower or higher, which may still be an unnamed socket, but
using 1s -1R /proc/ [0-9] */£d and looking for it often reveals the other end point's holder.
This is not a fool-proof method, because at times sockets are not created in pairs, but it's the
simplest way of deducing the number in absence of kernel symbols and /proc/kcore.

* - There are less often encountered types, such as raw sockets, which naturally maintain statistics in other files.
** - Technically, it's more accurate to read /proc/pid/net/family, since sockets may be contained in a namespace. /proc/net
offers the global namespace, however, so this works well too.

184

---

**Page 52**

Chapter VII: Through a Linux Lens

fdinfo

At first glance, the fdinfo directory looks unimpressive - just like fd, but without symbolic links
(or fancy colors). The information contained in fdinfo, however, is just as important as fd/, if not
more so.

For every open file descriptor, the corresponding fdinfo/## entry holds metadata about the file.
Device drivers and filesystem implementors may use this file to convey information about the
current state of the file descriptor back to user space, though in practice few do, leaving only the
default information maintained by the kernel itself, specifically:

e flags: The flags used in the open (2) system call, when creating or opening the file. These
are defined in the <fcntl.h> header file.

e pos: The current position of the "file pointer": i.e. the offset of the next byte to be read or
written from the file.

The pos statistic in a real gem, because it can let you monitor a process and figure out roughly
where along its timeline it presently is - all entirely unobtrusively. With a little bit of shell scripting,
you can harness this functionality to create custom tools to conditionally operate on a process, as
shown in the following listing:

Listing 7-1: A small script to watch and act on a file position in a process

PID=$1 # PID is first argument
FD=$2 # FD to watch is second argument
OFFSET=$3 # OFFSET to monitor is third argument

CUT_COMMAND='busybox cut' # needed because toolbox doesn't have cut built-in
# This isolates just the numerical offset from the fdinfo entry of $FD

# Get the data | isolate pos line | isolate numerical value
CUROFF="cat /proc/$PID/fdinfo/$FD | grep pos | S$CUT_COMMAND -d':' -£2>

if [[ $CUROFF -gt SOFF ]]; then
echo Do something
# Insert command to execute on trigger here
else
echo Nothing to do.
fi

The one drawback of the above script is that it relies on polling, rather than notification. Simply
put, the results will potentially change in between executions, and - depending on when you choose
to execute it - you might end up missing the precise offset you were looking for. This can be
assuaged by running the script at regular intervals, and/or changing the OFFSET parameter to allow
for more leeway (i.e. set the offset to a little bit before the actual required offset, and use
conventional debugging from the point on).

185

---

**Page 53**

Android Internals::A Confectioner's Cookbook (Volume 1)

status

The status proc entry is a one-stop shop for all the things you'd want to know at a high level on
the process being inspected. And not just what you would like to know, so much as what the kernel
would: The /status is effectively a human-readable dump of the task_struct, which is a
mammoth structure in the Linux kernel serving as the process control block (PCB). This is what the
kernel sees, at a glance, when handling a process:

Output 7-5: The annotated /proc/pid/status entry

shell@flounder:/proc $ cat /proc/511/status

Name: system_server # Same as /proc/511/comm

State: S (sleeping) # or R - running, T - Stopped, D - Uninterruptible (deep) sleep

Tgid: 511 # Thread Group id: The real process id

Pid: 511 # Thread, not process id

PPid: 211 # Parent Thread Group id

TracerPid: 0 # Any ptrace(2) attached process, like strace, gdb or debuggerd

Uid: 1000 1000 1000 1000 # Real, Effective, Set and File-System UIDs

Gid: 1000 1000 1000 1000 # Real, Effective, Set and File-System GIDs

FDSize: 2048 # Maximum # of file descriptors allowed

Groups: 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 1018 1032 3001 3002 3003 3006 3007
VmPeak: 2367448 kB # Virtual Memory high-water mark

VmSize: 2258636 kB Virtual Memory size, present

VmLck: O kB Memory locked by mlock(2) APIs

VmPin: 0 kB Pinned memory

VmHWM : 178100 kB RSSPeak - i.e. Resident memory footprint high-water mark

VmRSS: 151600 kB Resident memory footprint, present

VmData: 230448 kB Size of data segment (heap memory)

vmStk: 8192 kB
VmExe: 16 kB
VmLib: 120016 kB
VmPTE: 968 kB
VmSwap: 0 kB

Size of process thread stacks

Size of executable

Memory used by shared library (.so) files

Memory used by Page Table Entries

Memory used by process in swap (If no swap, always 0)

SigQ: 3/6826

SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000001204
SigIgn: 0000000000000000
SigCgt: 00000002000094£8
CapInh: 0000000000000000
CapPrm: 0000001007813c20
CapEff£: 0000001007813c20
CapBnd: 0000000000000000

Handled Signals/Size of signal queue

Bitmask of pending signals (for thread)

Shared pending signals for process

Bitmask of signals blocked (by SIG_BLOCK)

Bitmask of signals ignored (by SIG_IGN)

Bitmask of signals caught (by handlers)

Bitmask of inherited capabilities

Bitmask of permitted capabilities

Bitmask of effective capabilities

Bitmask of capabilities bounding set

Cpus_allowed: 3 Bitmask of CPUs allowed (3 = 0011)

Cpus_allowed_list: 0-1 List of CPUs allowed, for the hex-challenged
voluntary_ctxt_switches: 40684 # Voluntary (system call induced) context switches
nonvoluntary_ctxt_switches: 13471 # Nonvoluntary (preemption induced) context switches

#
#
#
#
#
#
#
#
#
#
#
Threads: 82 # Number of threads. If > 1, this is a multi-threaded process
#
#
#
#
#
#
#
#
#
#
#
#

There is copious output here, so it makes sense to go over the non-obvious fields step by step:
Sorting out the pid, tid, tgid, and ppid confusion

It's tempting to think that "pid" would stand for Process ID. Right? Well, tough. It doesn't.
Originally, Linux did actually use PID as Process IDs, but ever since the turn of the millenium Linux
joined other modern operating systems, in scheduling threads and not processes. As such, Pid
correctly describes the thread, and not the process id of the entry being inspected. A process is,
therefore, a group of threads sharing the same resources (virtual memory, file descriptors, etc), and
that is what is shown by the Tai field.

Some readers may first balk at this, especially when in the above example the Tgid fields and
Pid fields hold the same value. There's no contradiction here, though: For the main thread ofa
process, the Pid and the Tgid values will always match. This is, in fact, how one can easily
determine this is the main thread of the process - in other words, the first thread in the thread
group. For child threads, however, The Pid will change, while the Tgid will remain constant.

186

---

**Page 54**

Chapter VII: Through a Linux Lens

By the same reasoning, the Ppid field - Parent Process Identifier - is therefore more correctly
the Parent Thread Group IDentifier. Somehow, PTGID just doesn't sound as catchy, so it’s still
referred to as PPID. It's important to know one's lineage, because parents are responsible for
collecting their children's return code (returned from main() or a call to exit () ). Some parents
also drag all their offspring when they die, killing the entire process group.

Most UN*X tools are "conditioned" to only show statistics for main threads, and so the notion
(or illusion) or processes still works pretty well - and thus merits this section for explanation. The ps
command, in an effort to maintain backward compatibility with days of yore, maintains the lie by
calling Tgid as PID, and (when displaying threads, as in Linux's ps -L) will actually refer to the
Pid as Lwe. Android's ps, which displays threads with the -t switch, doesn't bother, and still calls
the field PID. The threads in any thread group can be seen by looking at the task/ subdirectory, as
shown in the following experiment:

Experiment: Viewing threads and processes in /proc

It often benefits an administrator or debugger to sift through the threads of multi-threaded
processes. The /proc filesystem offers per-thread statistics. Unlike Linux ps, which offers the 'I'
state to denote multi-threaded processes (in BSD mode), Android's ps tool only provides -t to list
all threads. You can use the Android top (1) tool to display the number of threads:

Output 7-6: Using toolbox top to show number of threads:

$ top
, IOW 0%, IRQ 0%
Sys 8 + Idle 609 + IOW 0 + IRQ 0 + SIRO O =

PID PR CPUS S VSS
19213 1 4088K
1 % 1 1004K

B

NAPNFRPOUSA

g system /system/bin/surfaceflinger
shell

BR

24788K

81204K

59788K

150116K Ss

141436K ° 0 c systemui
57220K bg u0_alé com.android.vending

1
0
0
0
1
0
0
0
1
1

ro

You can extend the pattern of iterating over processes, from the previous experiment, to also
iterate over a given thread group's threads. You can cd to /proc/tgid/task to find numbered
subdirectories corresponding to all threads in the group (including the main one). If you then cd
to the individual task/ subdirectories, you'll see they are similar to the main thread's entry
(/proc/tgid/task/tgid in fact being the same). The per-process and per-thread entries are essentially
the same (recall Linux sees threads, not processes), with nearly all process level attributes (maps,
fd, etc) remaining the same, but a few (syscall, wchan, and a few others) potentially different per
thread.

187

---

**Page 55**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Viewing threads and processes in /proc (cont.)

The status entry can be particularly confusing, because most of its entries apply to the thread
group (and are thus identical across threads) whilst others do change on a per thread basis. The
Tgid: for example, can indeed be corroborated to be the real process ID by the following:

Output 7-7: TGID vs. PID, hands-on

shell@flounder:/proc/211/task $ for t in *; do
> echo -n "PID St: "; grep Tgid: S$t/status;

> done

PID 19130: Tgid: 211

PID 19131: Tgid: 211
PID 19132: Tgid: 211
PID 19133: Tgid: 211
PID 19134: Tgid: 211
PID 211: Tgid: 211

Thanks to Android's best practice of naming individual threads, you can iterate over individual
threads of most multi-threaded processes and actually tell them apart. This is especially useful for
Dalvik apps (such as system server, q.v. Output 6-4), or even for Zygote itself - For example :

Output 7-8: Showing named threads

shell@flounder:/proc/211/task $ for t in *; do
> echo -n "PID St: "; grep Name: $t/status;

> done

PID 19130: Name: ReferenceQueueD

PID 19131: Name: FinalizerDaemon

PID 19132: Name: FinalizerWatchd
PID 19133: Name: HeapTrimmerDaem
PID 19134: Name: GCDaemon

PID 211: Name: main

A little Known fact is that you can cd directly into a thread. While listing /proc will only show
main threads (or kernel threads), invoking cd with a valid TID will simply switch into the per-
thread statistics, which are the same as what you would get through /proc/tgid/task/tid. When you
perform the list, procfs gets picky and filters out child threads. When you cd directly, procfs
doesn't care - if you specified a valid thread, child, main or kernel - you got it.

188

---

**Page 56**

Chapter VII: Through a Linux Lens

Thread states and context switches

While a thread would, optimally, want to always be running, more often than not it doesn't
need to. Threads spend their lifecycle executing every now and then, but more often than not they
are waiting. For an event, for user input, for I/O, maybe a mutex, or maybe just a chance to
execute, because all CPUs or cores are presently occupied by other threads. At any given time, the
kernel maintains the list of threads, and for each, it records the state.

The State: field in /proc/status shows the same state shown in Android's ps tool (or Linux's
ps, in BSD syntax). The states used are quite similar to states in other UN*X (such as Darwin and
other BSD), and in fact not unlike those of all operating systems, including Windows (though the
nomenclature is obviously different). The following state diagram depicts the transitions between

states:

Figure 7-1: The Linux thread state machine

Quantum expired

or preemption
Running Runnable
(executing) serena (queued)
a a
exit() > —- \/O or resource wait Fa Z
' me)
S . oy,
Zombie Sionel “My
(In process exit) gna we °
o
ot" Interruptible Uninterruptible
Sys_wakAt) / ge (sleeping) (sleeping, sig block)
Dead Stopped
(process has exited) (SIGSTP, TSTP)

Kernel State Constant ps Meaning
TASK_RUNNING(0) R Process is in running state, or runnable
TASK_INTERRUPTIBLE(1) S Process is sleeping, may be interrupted (by signals)
TASK_UNINTERRUPTIBLE(2) D Process is sleeping, may NOT be interrupted
TASK_STOPPED(4) T Process stopped (as per SIG_STOP, or TSTP)
TASK_TRACED(8) --- Process is being traced (single-step)
EXIT_ZOMBIE(16) Z Process has exited, waiting for RC collection
EXIT_DEAD(32) --- Process has exited, cleanup pending

189

---

**Page 57**

Android Internals::A Confectioner's Cookbook (Volume 1)

As shown in the diagram, there is no clear distinction between Running (i.e. presently executing
in a core or hyperthread) and Runnable (that is, on the run queue, but waiting for an available CPU)
- both are, from the kernel's perspective, the same state. A thread will actually run for as long as it
can, until one of two occur:

e Preemption: occurs when, due to an external interrupt, the kernel realizes that either the
thread quantum (allotted timeslice) has expired, or some higher priority thread has become
runnable. In both these cases, while the thread would no doubt benefit from prolonging
execution, it is kicked out in favor of another thread which takes its place, in what's known as
a context switch. This is obviously contrary to what the thread would have wanted (if it
had a will or a say), and is therefore considered nonvoluntary.

e Sleep/Wait: occurs when the thread simply has nothing to do at the present moment. This
can occur because of one of several reasons, namely:

o The user stopped the thread: by using the SToP signal. UN*X users are likely
familiar with the CTRL-Z combination, which causes the terminal driver to send the
signal to the main thread, thereby stopping the entire thread group - or what they
know as the process. A thread or group thus stopped can only be resumed with the
CONT signal, which is usually what £g or bg send. You can, of course, stop and
resume threads manually by using kill -STOP pidand kill -CONT pid,
respectively.

o The terminal driver stopped the thread: because of an attempt to run a full-
screen command (e.g. vi, more) in the background, or any background command on
input, or on output when the stty +tostop setting is set. The signal sent here is
TSTP, but otherwise behaves similarly to STOP.

o The thread actually yielded the CPU: which occurs when the thread calls
sleep (2) or other forms of delayed execution, or - more commonly - when the
thread is waiting for an IPC object (e.g. a mutex). This can also occur implicitly, when
the thread makes an I/O call that cannot be immediately serviced (i.e. is not present
in the buffer or page caches). Such I/O requires storage or human user input, both of
which are orders of magnitude slower than the CPU. The I/O system call therefore
chooses the greater good, which is to suspend the thread and put it on an I/O wait
queue*. When the I/O is complete (via an interrupt), the thread can be rescheduled,
possibly preempting another thread. In any of these cases, however, the thread
"agrees" (or, at least, acquiesces) the context switch, which is why it is referred to as
a voluntary context switch.

The distinction between voluntary and nonvoluntary context switches is an important one,
which is why you can find those statistics as fields in the status entry. A thread with an unusually
high number of nonvoluntary context switches keeps getting "kicked out" of the CPU when it still
needs it - which implies it might benefit from an increased priority (or is just a plain CPU hog).

The last two states shown in the diagram - Zombie and Dead - are non-states. A UN*X process
has a very clear raison d'etre - its return code, which it is supposed to provide in an exit (2)
system call, or as a return value from its main(). This code, however, must be picked up by the
parent process. This requires responsible parenting, in the form of calling one of the wait# (2)
system calls (usually after obtaining the child's SIGCHLD death notification) to collect the return
code. A main thread briefly enters the Zombie state when it exits (or returns from main (2) ), in the
hopes of being put out of its misery by its parent. If the parent fails to live up to its obligations,
however (by ignoring the signal or forgetting wait# (2) after fork (), as some programmers do),
the child is condemned to a Walking Dead state. Fortunately, UN*X Zombies are quite benign, and
don't actually consume any resources - memory, CPU, or other - aside from a process table entry.
The Zombies may also find peace when their recalcitrant parent dies (or is killed), leading to an
adoption by init () (PID 1), which is always happy to call wait# (2) and provide Requiem.

* - The choice of whether to enter TASK_INTERRUPTIBLE (which still accepts signals) or TASK_UNINTERRUPTIBLE
(which pends signals) is left up to the system call, or more accurately the driver in charge of servicing said call.

190

---

**Page 58**

Chapter VII: Through a Linux Lens

High-Level memory statistics

The /proc/pid/status entry also offers valuable high-level insights into process memory utilization
(note here, we use "process" rather than "thread", because resources are handled at the process,
not thread level). The various statistics are shown in Table 7-1:

Table 7-1: High Level memory statistics in /proc/pid/status

Metric Meaning
Virtual Memory high-water mark: The highest value obtained by VmSize
VmPeak eat .
over the lifetime of this process
VmSize Virtual Memory size, at the present moment.
VmLck Memory locked by mlock(2) APIs. For most applications, this is 0.
VmPin Pinned memory. For most applications, this is 0.
VmHWM Resident memory footprint high-water mark: The highest value obtained by
VmRSS over the lifetime of this process
VmRSS Resident memory footprint, at the present moment.
VmData Size of data segment - This is the size of the process heap memory
VmStk Size of process thread stacks
VmExe Size of executable
VmLib Memory used by shared library (.so) files
VmPTE Memory used by Page Table Entries
Memory used by process in swap (In Android - no swap, ergo always 0,
VmSwap ,
unless using swap to ZRAM)

Looking at the high level statistics can often provide a quick diagnosis as to memory hogging
problems - particularly high levels of vmkss:. To gain more insights into memory problems,
however, we need to consider the more fine grained statistics of /proc/smaps - and memory
management in general.

191

---

**Page 59**

Android Internals::A Confectioner's Cookbook (Volume 1)

User mode memory management

Programmers don't normally pay attention to memory. It's a given that each process gets its
own address space, wherein it can allocate memory freely according to need, and be assured that
the kernel will handle all the minutiae. The address space is private - that is, belonging only to this
process, and virtual - i.e. abstracted from the actual RAM by the kernel and memory management
unit.

In practice, however, memory is one of the most critical bottlenecks an application can face.
Improper memory management not only has an adverse effect on the mismanaging process, but
also on the entire system. The effect is further exacerbated on Android: whereas on Linux memory
allocations which would deplete the RAM could be backed by swap (leading to excessive swapping
and performance degradation but still being satisfied), Android has no swap - and, as a
consequence, it's simply not possible to deplete the RAM without triggering a global out-of-memory
condition. At that point, the only way to recover RAM would involve killing a victim process to
recover its RAM.

Android does a remarkable job of optimizing the available memory, to compensate for the lack
of swap. The very design of the Dalvik Virtual Machine emphasized sharing as much virtual memory
as possible. Indeed, multiple instances of the traditional Java VM (such as that of Sun's J2ME)
simply could not be satisfied without 100+ MB of RAM per instance. Dalvik VMs instances, by
contrast, are nearly all shareable, resulting in a fairly low memory footprint for individual apps.

Virtual Memory classification and lifecycle
It's tempting to think that “all virtual memory is the same", but that is far from true. Virtual
memory can be classified by no less than four types, which impact its usage - and, even more

importantly, its release. Pages have their own lifecycle, depicted in the following figure:

Figure 7-2: The page lifecycle

"| Active Dirty [

Active Clean

Inactive Dirty

Page Out or timeout

Free
Inactive Clean |< back gee
To swap or file
State Meaning

Free Page is unallocated
Active Clean Page is claimed by one or more processes, but not modified
Active Page is claimed by one or more processes, and modified
Inactive Dirty Page has aged since last access, and needs to be commited
Laundered Page is selected for committing (writeback pending)
Inactive Clean Page has been committed (or not modified). May be reused or freed

192

---

**Page 60**

Chapter VII: Through a Linux Lens

Named (mmapped) vs. Anonymous

The first classification of a memory page denotes its source - mapped pages are pages taken
from files on the storage (disk, flash, or network file system). The pages are loaded from a file, (via
the kernel's page cache), contiguously into the process’ virtual memory. The file name serves as a
name for the memory itself, which is why mapped pages are often also referred to as named
memory.

By contrast, some memory is not file backed, and is created ad-hoc for the process' immediate
need. This includes memory used by the stack or the heap, when the program sets up a stack frame
or calls malloc (3). This memory has no backing in a file, and therefore has no name - which is
why it is often referred to as anonymous memory.

The maps per-process proc entry will show you all memory mappings. Named mappings are
easy to see because the device and inode number, along with the corresponding filename, are
clearly listed. Anonymous file mappings have a no numbers, but "special" anonymous mappings -
such as the stack or heap, are clearly shown.

Dirty vs. Clean

Once a page is loaded into memory, it may remain unaltered - used as read-only memory, or it
may be modified by the process for whatever reason. Unaltered memory is referred to as clean
memory, whereas modifying memory makes it dirty.

This distinction is more than just cleanliness - The system needs to know if a page is dirty or
clean for several reasons, including knowing what to do when the page has spent too much time in
memory, and how it affects sharing - which brings us to the next classifications:

Active (referenced) vs. Inactive

Virtual Memory pages , when mapped to RAM, have an "age". The kernel and MMU work
together to maintain a reference mechanism, tracking the Least Recently Used (LRU) pages. When
a page is accessed, it is immediately marked as Active. If left unused for more than a given period,
the status is changed to inactive.

The activity indication is important for purposes of purging and writeback. Purging refers to
the process of discarding a page, when it is no longer required. If the page is both inactive and
clean, it implies that it has either a zeroed page, or it has been backed up to storage. In either case,
it can be rid of immediately, to make room for another process’ virtual memory paging request.

Writeback refers to the process of taking dirty pages, and writing them back to storage -
commonly, the files whence they came, but - in the case of anonymous memory - to swap. Mapped
pages are especially important to write back within reasonable time, because the system could face
power loss (or a crash) unpredictably. Mapped pages not written will result in data loss. The kernel
therefore maintains page expiration parameters in /proc/sys/vm. Anonymous pages are written to
swap (compressed RAM, in Android systems which support it). If there's no swap (or compressed
RAM) to write back to, the system faces an Out-Of-Memory condition (as we describe later).

Private vs. Shared

Memory that is unique to the process is considered private. This implies that only the process
has access to the memory page, and no other process can physically access the memory. Normally,
this is when a process requests a file mapping using mmap (2) with the MAP_PRIVATE flag, or
(more commonly) allocates anonymous memory using malloc (3) or new.

Memory can also be shared, in between two or more processes. This is usually the result of a
deliberate sharing done by the programmer, using memory sharing calls such as mmap (2) with the
MAP_SHARED flag, or other mechanisms (such as System V shm* APIs, or - in Android -
/dev/ashmem). This is known as explicit sharing, because the process specifically tells the
kernel - I want this memory to be shareable with others.

193

---

**Page 61**

Android Internals::A Confectioner's Cookbook (Volume 1)

Shared memory may be mapped in different virtual addresses in process A and process B, but
both will eventually get to the same physical page. This means that there is only one physical copy
of shared memory in the system - after all, why waste two RAM pages with exactly the same
content? This also has the upside of relieving the kernel from having to maintain the sharing by
updating multiple copies of memory on change. If there's only one copy mapped to all processes,
any change in that copy is instantly reflected among all processes.

Things get a little bit more complicated: Sometimes, a process may request private memory,
but the system may decide to share it anyway, without informing the process - in what's known as
implicit sharing. Examples of this abound - in fact, most memory is implicitly shared, unless
otherwise stated. For example, consider libraries and frameworks: Each process certainly needs a
copy of them, but the vast majority of the processes use the copies verbatim, not making any
changes. Library and framework code, for example, is mapped read-only, and therefore, by
definition, cannot change. It doesn't make sense, then, to map individual copies of libraries
(especially commonly used ones, like Bionic), when all copies are the same. In these cases, even
though the process may request MAP_ PRIVATE, the kernel basically says "sure, sure", but performs
sharing anyway, outright lying to the process, which remains entirely oblivious.

To maintain this elaborate ruse, the kernel does require a little bit more overhead: If memory is
implicitly shared, and one of the parties tries to modify it anyway, the kernel will have to allow that
party to modify the memory, without affecting any of the others. This is when the kernel employs
copy-on-write, which involves intercepting the write attempt (by a page fault), then creating a
new copy which can be written to, and remapping that copy to the process virtual memory, instead
of the original page, which is left unmodified and mapped to all other parties' address space.

Experiment: Examining address space mappings through /proc/pid/maps

The per-process procfs maps entry provides a full layout of the process address space,
enabling you to quickly determine which files have been mapped, alongside the anonymous
memory regions. Output 7-9 demonstrates the entry for the shell (on a 64-bit system), with
annotations:

Output 7-9: Examining a process address space (e.g. the shell) through /proc/pid/maps

shell@flounder:/ $ cat /proc/$$/maps

5579579000-55795bc000 r

55795cb000-55795cd000 r

55795cd000-55795ce000 r
e000-55795cf£000 rw
6000-559e90c000

b000-7£82a12000 r 00 0 103:0 /system/1ib64/libc.so

/system/1ib64/libc.so
0008b000 3: Oc 275 /system/1ib64/libc.so

7££66d9000-7££66fa000 xr 00000000

You can see even more detail by examining the smaps per process entry. This provides the
same information as maps did, but with the additional breakdown by classification for every region
- but that will be demonstrated shortly, in the next experiment.

194

---

**Page 62**

Chapter VII: Through a Linux Lens

To view memory statistics on a system-wide level, you can consult the /proc/meminfo file. The

file (used by utilities like top and vm_stat uses the same nomenclature and classifications just
defined:

Output 7-10: Examining system wide memory utilization with /prc/meminfo

shell@flounder:/ $ cat /proc/meminfo

AnonPages:
Mapped:
Shmem:

Memory Metrics

To calculate memory statistics, one has to take into account quite a few factors, such as

whether or not memory is resident, shared, and other parameters. We can start off with the
following simple formula:

VmSize = VmRSS + VmFileMapped + VmSwap + VmLazy

In plain English, this means that the virtual memory of a process may be classified into four

disjoint categories:

VmRSS: The Resident Set Size - are those pages of virtual memory which are presently
backed by physical RAM pages. This may be because they have been recently active, or - in
some cases - because the process (or kernel) requires them to be locked in memory. The
resident memory may further be subclassified as Unique (private to this process) or Shared
(in between one or more processes).

VmFileMapped: Pages which were retrieved from files, by means of the mmap (2) system

call, may be written back to the files at any time to free memory. In fact, in most cases if the
pages remain clean (unmodified), they can simply be discarded as - if need arises - they can
always be reloaded from the files, which are still on flash/disk. The size of pages in this
category is not directly reported in /proc/pid/status, but can be figured out from /proc/smaps,
and - on a system-wide level - from /proc/meminfo.

VmSwap: Pages which resulted from memory allocation (i.e. malloc (3) or similar) do not
have any file backing. These are also known as anonymous pages, since they have no
name (read: filename) to back them up. It follows that there is no way to write them back
out. In Linux, swap space comes to the rescue, as a portion of storage set aside to back
anonymous pages. In Android, however, there is no swap. This value is therefore almost
always 0, unless the system swaps to compressed RAM (ZRAM).

195

---

**Page 63**

Android Internals::A Confectioner's Cookbook (Volume 1)

e VmLazy: Programmers are a greedy lot, often allocating far more memory than they actually
need. The kernel takes a lazy approach to allocation, preferring to set aside pages "on paper"
until they are actually required, or written to. These pages are allocated in the process Page
Table Entries (visible in /proc/pid/status aS VmPTE: ), but the actual allocation is deferred until
a pointer to the page is actually dereferenced. The kernel then experiences a page fault from
the MMU, which reports - correctly - that the page does not exist. The kernel then proceeds
to actually allocate the page. Using lazy allocation saves a great deal of memory, but does
impact performance marginally. A worse scenario occurs when the page fault cannot be
satisfied due to no available physical pages, and no way to write back any to disk. That's
when an Out-of-Memory (OOM) condition occurs, which we discuss later in this chapter.

It's tempting to sum up VmRSS over all processes in order to calculate the overall RAM
footprint. Doing so, however, would be wrong - because Some of the resident memory of the
process may in fact be shared with others, in which case a simple summation would end up
overcounting the shared regions. A more accurate measure is needed, and this is what Linux offers
with the PSS - Proportional Set Size statistic. In mathematical speak, PSS would be defined as:

- Shared;
PSS = USS + >
i

i=1
Where:
s = #of shared regions
Shared; = Size of shared region |

Dp; = # of processes sharing region i

If, like most non-math-types, you find the equation a tad alarming (or promised yourself to not
ever use Sigma notation again), this can be put in words, like so:

e PSS will count 1K for every 1K of private memory (USS). That is, if a process has a private
memory page, it counts in full for purposes of calculating the PSS footprint

e PSS will only count 1/n K for every 1K of shared memory, with "n" dependent on the number
of processes sharing this region. Because there may be more than one regions, we need the
Sigma notation - which basically says, add 1/n, for the first region found, then add another

1/n> for the second region found (assuming np sharers), etc.

This might seem odd at first, but when you take the sum of PSS over all processes in the
system - mathematical magic adds up the shares in a way that every shared region is counted in
full, and exactly once, for the purposes of determining the footprint (If you want a slight challenge,
you can work out the (double) sigma notation required to prove the correctness of this claim).

Fortunately, PSS measurements prove far more useful than the algebraic equations backing

them, and are readily obtainable (with virtually no need for math) directly from the /proc/smaps file.
This is best exemplified in the following experiment:

196

---

**Page 64**

Chapter VII: Through a Linux Lens

Experiment: Observing RSS, USS and PSS through /proc/pid/smaps

The per-process smaps entry breaks down memory regions from the maps entry and provides
detailed information on each. For this experiment, find a binary that isn't concurrently executing as
another process, and doesn't terminate quickly. A good candidate for that is ping, which is an
actual binary (not a toolbox tool), and will run indefinitely.

Start ping with some address - it doesn't even matter if the address is reachable - what
matters is that ping will run. If you choose another binary, that's fine too - the choice of binary is
entirely inconsequential for this experiment - what matters is that the binary loads, and creates a
process instance, which you can then suspend. Once the binary is running (possibly paused for
input), hit CTRL-Z to suspend it and go back to a prompt, or leave it running in the background.
Then, inspect the first 10 or so lines of its smaps entry. Using ping, it will look something like this:

Output 7-11(a): Examining the USS, RSS and PSS of a single instance of a given binary

shell@flounder:/system/bin $ ping 1.1.1.1 > /dev/null &
] 0117
@®flounder:/system/bin $ more /pro
/system/bin/ping

Referenced:

Anonymous:
AnonHugePages:

Swap:

KernelPageSize:
MMUPageSize:

Locked:

VmFlags: rd ex mr mw me
dw ..

What do we see in the output?

e The first memory region is loaded from /usr/bin/ping on disk (no surprise here). The region
is readable, executable, and (seemingly) private (1-xp). It was loaded from device
103, 0d, inode #463.

e The VmSize of this region is 36Kb. Of which, 4k have been immediately freed - because the
Rss is 32k. This amounts to a portion of the ELF header, which has no practical use in
memory during runtime.

e The 32k of RSS are all private, and clean: Private, implies unique to this process (i.e. USS),
and clean implies that they have not been modified since their loading. All 32k are also
recently active (Referenced), which again is no surprise, since ping is executing. The pages
are not anonymous (because they are mapped to a file).

e Consequentially, the PSS is 32K. With no shared memory, every 4k of USS map to 4K of
PSS.

So far (hopefully), so good. But what happens when we start another instance of ping (or
our process)? Doing so, we then inspect the smaps entry of the first instance (not the second!),
and see that it has changed!

197

---

**Page 65**

Android Internals::A Confectioner's Cookbook (Volume 1)

" . ,
Experiment: Observing RSS, USS and PSS through /proc/pid/smaps (cont. )
Output 7-11(b): Examining the USS, RSS and PSS of the first of two concurrent instances of a given binary

# Once again, start the binary in the background - collect PID
$ ping 1.1.1.1 > /dev/null &

shell@flounder:/system/bin
[2] 0130
shell@flounder:/syste $ more /proc/20117/smaps
55705e3000-55705ec0 <p 00000000 103:0d 463 /system/bin/ping
: # VmSize unchanged

# RSS unchanged

# PSS drops by half because

# All 32k are now shared!

AnonHugePages:
Swap:

Kernel PageSize:
MMUPageSize:

rd ex mr mw me

Comparing the two outputs you can see that most metrics in the original process have not
changed - The VmSize is still 36k with a 32k RSS. The RSS, however, is now all shared - between
the two instances of the binary - and therefore the PSS has dropped by half, to 16k.

Running this example with another instance of the process will bring down the PSS to 10k
(technically 10.6k, but rounded down), and with four instances - to 8k (32k divided cleanly by
four). Killing instances reduces the number of sharers, and brings up the PSS value.

Note, that throughout the example, the region remained seemingly private (r-xp

in both outputs). This is obviously false, since smaps clearly shows the region
becomes shared. This paradox is resolved by explaining 'p' not as private, but as
MAP PRIVATE - i.e. the argument to mmap (2) when mapping the region. This is the
same "ruse" that was previously discussed when explaining private/shared memory.
Stated otherwise, the process mapped this region as private, and the operating system
plays along - but if another process maps this same region, the kernel reserves the right
to make this implicitly shared between the processes, so long as neither process
actually writes to (dirties) the region. If a write occurs, the writing process triggers a
copy-on-write fault, which forces the kernel to actually allocate another copy of the
page(s) written to, so as not to violate the existing copy. This is in contrast to 's' in the
permission flags, which means explicitly shared (i.e. MAP_ SHARED in the mmap (2)
arguments) - denoting that the region can be dirtied and still remain shared as a single
copy.

The experiment hopefully served as a simple example of how PSS is calculated. ‘Simple’,
because this was a simple case where all memory was shared, thereby reducing USS to zero, and
making the PSS calculation straightforward. Other regions may be mixed - both private and shared,
which makes PSS calculation a bit more challenging, but fortunately smaps does that automatically.

If you're not a fan of parsing /proc/smaps manually, there's a tool for that - two, in fact. This is
shown in the next experiment.

198

---

**Page 66**

Chapter VII: Through a Linux Lens

©) Experiment: Observing RSS, USS and PSS through procrank and librank

The AOSP provides two useful tools to show memory statistics - procrank and librank. These
are not present in most production devices, but it's a simple enough matter to copy them from the
emulator image to the device, along with their dependency, /system/lib/libpagemap.so. This is
shown in the following output:

Output 7-12: Moving binaries from the emulator to a real device

morpheus@forge (~/tmp)$ adb -s emulator-5554 pull /system/xbin/procrank
~/tmp)$ adb -s emulator-5554 pull /system/xbin/librank
(~/tmp)$ adb -s emulator-5554 pull /system/1lib/libpagemap.so

# kill emulator or use -s with serial number of device from adb devices

morpheus@forge (~/tmp)$ adb push librank /data/local/tmp
(~/tmp)$ adb push procrank /data/local/tm

morpheus@forge (~/tmp)$ adb push libpagemap.so /data/local/tmp

On the device, you'll need to make the binaries executable (by using chmod (1) ), and then
execute them. Because the library dependency is also in /data/local/tmp, and libraries are searched
for in /system/lib[64], you'll need to alter the library load path. On a rooted device, this is not
necessary if you drop the library dependency in /system/lib.

Output 7-13: Moving binaries from the emulator to a real device

# On device:
®htc_m8wl:/ § chmod 755 /data/local/tm rocrank
shell@htc_m8wl:/ $ /data/local/tm rocrank

shell@htc_m8wl:/data $ LD LIBRARY PATH=/data/local/tmp /data/local/tmp/procrank
PID Vss Rss Pss Uss cmdline
234 331600K 89211K 61314K 49124K system_server

Once you have procrank and librank copied (or, if you just run them on the emulator), you can
turn to analyzing their output. Both tools operate by iterating over the per-process smaps statistics
(newer versions work with the pagemap entry), but they differ in how they output the statistics:
procrank does so by sorting processes in descending order of memory usage, while librank sorts
regions of memory by the processes using them. There's a lot to be learned from the output about
memory utilization (and optimization) in Android. Starting with pagemap:

Output 7-14: The output of procrank from the L Emulator

root@generic:/ # procrank

PID Vss Rss Pss Uss cmdline

354 631600K 99212K 60712K 48784K system_server

709 578240K 91200K 45218K 24512K com.android.systemui
581 565940K 72876K 43295K 38940K com.android. launcher
52 102852K 47784K 24356K 2132K /system/bin/surfaceflinger
538 540284K 44108K 16408K 13284K com.android.phone

66 508532K 46416K 14799K 8948K zygote
955 531912K 30760K 6756K 4700K com.android.calendar
843 522168K 30364K264K 4396K com.android.providers.calendar
1077 521044K 28308B499K 3668K com.android.browser
978 520144K 29004K311K 3336K com.android.deskclock
1037 520732K 27380B082K 3484K com.android.exchange

199

---

**Page 67**

Android Internals::A Confectioner's Cookbook (Volume 1)

©) Experiment: Observing RSS, USS and PSS through procrank (cont. )

As the output shows, processes are ranked by descending order of Vss (as per -v, the
default; you can also sort by -pss, -rss, or -uss). More advanced options will show only cached
(-c) or non-cached (-Cc) pages - try -h for more options.

In the output, however, something stands out very quickly - though Vss sizes are humongous
(565M for the Launcher, really?), the actual RSS sizes are small (indicating plenty of discarded
mappings), and the PSS sizes are smaller still. As you can see, the average unique footprint of
apps is no more than a few MB! About 85%-90% of the RSS of the average app is all shared,
reducing its PSS dramatically. This shareability is owed to the structure of Zygote and the Dalvik
VM (ART included) which maximize shared memory in ways Java never could (but still not as
efficiently as iOS, some would argue).

You can work back to see how much memory is shared by subtracting the USS measure from
the RSS. Subtracting the USS from the PSS will give you the weighted average of the shared
regions, and dividing the shared memory size by this amount will give you a rough idea of how
many processes are sharing the same regions. This is a rough idea only, because summing up PSS
loses some granularity - different regions likely have a different number of sharers.

The 1ibrank tool's output is slightly different, as it is sorted by memory region. Otherwise,
however, the terminology remains the same. The following output demonstrates the usage of the
boot.oat shared region, which holds precompiled framework classes in ART:

Output 7-15: The output of librank demonstrating sharing on the ART precompiled classes

root@generic:/ # librank
RSStot VSS RSS USS Name/PID

27179K /data/dalvik-cache/arm/system@framework@boot.oat
48556K 19576K 3268K system_server [354]
48556K 13488K 2112K zygote [66]
48556K 13984K 2192K com.android.phone [538]
48556K 14800K 744K com.android.systemui [709]
48556K 11880K 324K com.android.launcher [581]
48556K 10544K 160K com.android.inputmethod.latin [500]
48556K 9268K 104K android.process.media [766]
48556K 9048K 64K com.android.email [997]
48556K 8200K 96K com.android.server.telecom [532]
48556K 8628K 20K com.android.calendar [955]
48556K 7960K 12K com.android.providers.calendar [843]
48556K 7280K 24K com.android.deskclock [978]
48556K 7220K 20K com.android.browser [1077]
48556K 6772K OK com.android.exchange [1037]
48556K 6132K OK com.android.dialer [1061]
48556K 5796K 4k com.android.sharedstoragebackup [1096]

librank shows, yet again, the efficiency of sharing - The VSS associated with the boot.oat is
some 48MB. In practice, however, less than half is resident, and - in most processes unique
memory footprint of the oat is in the low KB.

Newer versions of Android make use of an even more clever forms of sharing, through the
Linux kernel's Kernel Samepage Merging (KSM) mechanism. This features lets the kernel auto-
detect identical physical pages in memory (by comparing hashes), even if they are not memory
mapped. If an identity is detected, the pages can be merged, subject to the usual copy-on-write
restrictions. KSM has been a feature in the Linux kernel as of 2.6.27 or so, but has only recently
entered Android.

200

---

**Page 68**

Chapter VII: Through a Linux Lens

Out of Memory conditions

Despite all the extensive memory sharing in Android, along with tricks like KSM or ZRAM, lack of
real swap space is an inherent problem. Android is not at fault here - swap and flash simply do not
go well together, due to flash memory's limited Program/Erase (P/E) cycles. As a consequence,
running out of memory at any given time is a clear and present danger.

The Linux kernel has long had a mechanism to deal with memory shortage. This mechanism -
called OOM (Out-Of-Memory) is triggered when a memory request cannot be satisified. In Linux, this
happens rarely - if the system is low on RAM there is usually ample swap space to fall on. It's only
when the system is both out of RAM and swap space that OOM is triggered.

OOM isn't a thread - it's implemented as a code path following the page fault which occurs. The
code looks through the list of processes, and attempts to find the most suitable candidate, whose
sacrifice will result in the best memory gain for the system. All processes are candidates on this
"death row" , sorted by their com_score - a heuristically devised score which evolved as did the
kernel. This score is visible in the per-process /proc/pid/oom_score as a read-only pseudofile.

The problem with the heuristic is, that - as will all heuristics - it doesn't always reliably work.
Often times, innocent processes are sacrificed just for being with the wrong score at the wrong
time. Execution is imminent and swift, with no saving throw - essentially a kill -9 - and there is
nothing the victim can do about it.

It is for this reason that the Android application lifecycle exists with the perpetual fear of
untimely death. Applications are not guaranteed persistence in any way, and are instead given
callbacks to save their state (as an opaque android.os. Bundle), with the only promise that, if
they are killed, they will be reincarnated with that bundle. An application has no way to predict
when and even if it may be terminated. As opposed to iOS's jetsam (a mechanism designed for a
similar functionality), the application doesn't even leave a tombstone (though some detail to the
kernel log is saved).

In an effort to bring a bit more determinism to the heuristic, Linux offered a method to adjust
the score from user space. First, as /proc/pid/oom_adj and (in later kernels) as
/proc/pid/oom_score_adj. These files enable a user space process to add a modifier to the score - a
negative modifier to reduce the score (thus making the process less killable) or a positive modifier to
increase the score (effectively giving the process suicidal tendencies).

Android's system processes use this mechanism to make themselves unkillable. /init and its
cohorts from the various .rc files give them an com_adj of -16 or -17 (which completely disables
OOM for the task). In newer kernels, setting the com_score_adj to -1000 achieves a similar
result, which effectively makes their score close to (if not) 0.

In the wrong hands, this could have also been abused by apps (after all, who wouldn't resist
the temptation for immortality?) but Android's ActivityManager automatically resets the score
adjustment along various stages of the application's lifecycle (as we discussed in Volume II). As of
Android L, The ActivityManager relies on the 1mkd (discussed in Chapter 5), because the
adjustment files are owned by (and writable to) root only.

Android takes another precautionary measure, in the form of the LowMemorykiller (Imk). This is
an Androidism which enhances OOM by preemptively killing processes before a real OOM condition
is triggered. In previous Android versions, init would set the module's parameters via sysfs on
startup. With L, init merely ensures file permissions on the sysfs pseudofiles, leaving the task to Imkd
instead.

201

---

**Page 69**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: OOM memory adjustments in action.

You can observe the OOM score adjustments in real time by examining the procfs entries
during application lifecycle. For this experiment, open an ADB shell while using an app. For
example, if you're using the Chrome web browser, you'll see:

Output 7-16(a): Viewing an active application's OOM scores

@®flounder:/ # ps _| grep chrome
211 2295800 167140 £fffffFf a7058b1lc S com.android.chrome

flounder:/ # cat /proc/12079/o0om score adj

@flounder:/ # cat /proc/12079/o0om adj,
@®flounder:/ # cat /proc/12079/oom score

Moving the application to the background (by simply pressing the home button) will
automatically reflect in OOM. The oom_adj increases, and the score shoots up accordingly

Output 7-16(b): Viewing an active application's OOM scores

root@flounder:/ # cat /proc/12079/o00m adj

6

root@flounder:/ # cat /proc/12079/00om score adj

411
root@flounder:/ # cat oom score
470

In Android L, you can also attach a trace to 1mkd during the application lifecycle events, to
see incoming messages from ActivityManager to 1mkd, in order to adjust the scores. This
was shown in the Experiment in Chapter 5 (specifically, output 5-6). Suspending 1mkd (by
kill -STOP ) will prevent any OOM modifications.

202

---

**Page 70**

Chapter VII: Through a Linux Lens

Tracing System Calls

Virtually any "meaningful" operation performed by a user-mode thread requires some kernel-
involvement. Whether it is dealing with a file, opening a socket, or handling any type of resource
outside one's own previously allocated virtual memory, a user-mode thread must request that
service from the kernel, by means of a system call.

System calls require the user mode process to first traverse into kernel mode. The method of
doing so differs with each architecture, but always involves a special machine instruction - ARM's
Svc (a.k.a SwI), or Intel's SYSENTER (or SYSCALL). These instructions set the processor mode to
privileged (supervisor) mode, and are setup by the kernel upon boot to transfer control to a
predefined kernel entry point - system_cal11. All system calls are thus funneled to one function.
The system call number (passed in ARM's +12 or Intel's EAX) is used to redirect execution to the
specific system call implementation, by consulting an internal table.

Given all the above, it should be clear why system calls deserve special focus, when it comes to
debugging and tracing processes. Most of the time, the internal operations inside a process -
changing this or that variable - aren't of too much interest, if only because they are so plentiful and
hard to trace. Operations on files or sockets, however, are especially interesting, and tracing system
calls provides a simple way to trace these operations, among others.

The toolbox ps tool

Toolbox's ps tool, however crude, does offer two valuable fields pertaining to system calls:
WCHAN and Pc. The first denotes the "Wait Channel", which is the kernel address the entry is
presently in, or -1 (Oxfffffff) if this cannot be determined (Recall each line in ps refers to a kernel
thread or the main thread of a process, unless ps -t is used). The second is the return address (in
user space), where execution resumes after the system call. Resolving the kernel address requires
some manual work, as shown in the following experiment:

tc . ,
Experiment: Manually resolving toolbox ps's WCHAN value

When faced with a WCHAN address - or any kernel address - you can follow the simple method
shown here to use /proc/kallsyms and resolve it to a more readable symbol. You start at the exact
address - which never produces a match, since entries in kallsyms are only for entry points, and
the WCHAN is inside a function. You then go back by removing the least significant digits, taking
advantage of grep's ability to match the prefix. At some point, grep will match one or more
addresses - and the closest one to the one checked is the name of the function the kernel is in.

Output 7-17: Resolving a kernel address using /proc/kallsyms

dgeneric:/# echo 0 > /proc/sys/kernel/kptr restrict

ic:/data # grep _c0029d4 /proc/kallsyms

data # grep c0029d /proc/kallsyms
eric:/data # grep c0029 /proc/kallsyms

4f£0 T exit_signals

eric:/data # grep c0029c /proc/kallsyms

4 T do_sigtimedwait

One caveat to keep in mind - make sure to find the closest symbol before and not after the
address you're looking for. Sometimes (like in this example) the closest symbol may wrap, and
other times grep might return matches which are after your symbol (and therefore incorrect).

203

---

**Page 71**

Android Internals::A Confectioner's Cookbook (Volume 1)

wchan and syscall

The /proc filesystem also offers system call tracing mechanisms. The wchan per-thread entry,
like the toolbox ps output, shows the location in kernel mode where a thread is sleeping (or 0, if
the thread is presently active), but also resolves it to the closest symbol, saving you the hassle of the
previous experiment. What more, it works even if the /proc/kallsyms file restricts addresses.

In some kernels, the syscall per-thread entry offers even more detail: It captures the system call
number, along with arguments, that the thread is in at the time of polling. The format of this is
demonstrated through Output 7-18:

Output 7-18: The syscall and wchan procfs entries

root@flounder:/proc/12079 # cat syscall

0x10 Ox7£c139b110 0x10 0x2324a 0x0 0x8 0x7f£c139b040 Ox7£a7058blc

2079 # cat wchan
SyS_epoll wait

You can resolve the program_counter value - which is also the value quoted by toolbox top's
Pc - using the method shown in the previous experiment. A caveat with system call numbers,
however, is that they are not guaranteed to remain constant across architectures. The system call
numbers of Intel and ARM are understandably different, but more surprisingly those of 32-bit and 64-
bit are sometimes different. You will need the specific system call file for your architecture, which you
can find in the Android NDK, under platforms/android-APIversion/arch-arch/usr/include/asm/unistd.h,
replacing arch with arm, arm64, x86 or x86_64. Fortunately, kernels with syscall procfs entry normally
have wchan as well, so you can resolve the syscall number via wchan, as demonstrated above. Most
kernels also have a stack entry, which details the kernel stack.

The strace tool

The methods shown so far all used polling - i.e. you could get an exact reading on a system
call, but were responsible for initiating the reading, and could only capture one result at a time. This
is useful in case of diagnosing a hanging or unrespnsive process. Most system call tracing, however,
is best performed as an on-going operation, attaching to the process as unobtrusively as possible,
and getting notifications on every system call it performs.

This is where strace comes into play. This powerful binary, which has been used several times
by now in this book to trace and explain the internals of processes, is utterly invaluable as a tracing
tool. A complete example of its usage would likely take up a chapter by itself, but table 7-2
summarizes some of the more useful switches:

Table 7-2: The more useful switches of strace

Switch Use
-i Print instruction pointer at time of syscall
-t[t{t]] Print timestamp, with/without usecs
-f Follow the clone() syscall, auto-attaching to child processes/threads
-o file Save output to file
-vi[v] Verbose mode for various syscall arguments

strace is exceptionally good at understanding the system call arguments (even more so when
-v/-vv is used. At the time of writing, there is no Android-aware version of the tool, nor is there an
ARM64 compatible version. The jt race tool, from the book's companion website, provides an
strace Clone which addresses both these issues.

204

---

**Page 72**

Chapter VII: Through a Linux Lens

Summary

This chapter focused on the usage of the /proc file system - in particular, the per-process
entries in /proc/pid and per-thread entries in /proc/pid/task/tid - and the plethora of information they
provide, to allow for powerful native-level debugging and tracing of processes. The methods
demonstrated apply to mainline Linux in the same ways, because procfs is an integral part of the
Linux kernel.

References and Files Discussed in this Chapter

Reference Provides

/proc/pid/fd
/proc/pid/fdinfo

Information about open file descriptors for process

/proc/pid/maps Address space of process, as list of mapped and anonymous regions

/proc/pid/smaps As per /proc/pid/maps, but with per-region statistics

/proc/pid/status | Information from process or thread's control block (kernel's task_struct)

1. www.kernel.org/doc/Documentation/filesystems/proc.txt Documentation about the procfs

filesystem entries.

205

---

**Page 73**

VIII: Android Security

As with other operational aspects, Android relies on the facilities of Linux for its basic security
needs. For most apps, however, an additional layer of security is enforced by the Dalvik Virtual
Machine. Android Security is therefore an amalgam of the two approaches - VM and native - which
allows for defense in depth.

This chapter starts by providing a brief insight into threat modeling: A practice taken by security
experts to try and analyze the possible attack vectors and threats which may compromise a device.
Malicious apps, and theft are just two of the possible threats considered, as mobile security must
address all the "traditional" faults of desktop security, and then some.

We continue by exploring the Linux user model, and its adaptation to the Android landscape.
Starting with the native Linux permissions, and the clever usage of IDs for Apps and group
membership. We then proceed to highlight capabilities, an oft overlooked feature of Linux used
extensively in Android to work around the inherent limitation using the almighty root uid in the
classic model. Next is a discussion of SELinux, a Mandatory Access Control (MAC) framework
introduced in 4.3 and enforced in 4.4. Lastly, we consider various protections against code injection,
the bane of application security.

At the Dalvik level, we consider the simple, yet effective permission model enforced by the
Virtual Machine and the package manager, as well as the bindings to the Linux level. But up to this
point, both Linux and Dalvik can be thought of as aspects of application level security.

We therefore next consider user-/eve/ security: protecting the device against human users by
locking the device. No longer the domain of simple PINs and patterns, device locking methods get
ever more innovative, and have expanded to include biometrics as well. As of JB, Android allows
multiple users to coexist, each with his or her own private data, and set of installed applications, and
so the implementation of multiple users is covered as well.

At this point, we turn to a discussion of encryption on Android. Beginning with aspects of key
management, we explain the inner workings of the keystore service, and the maintenance of
cetificates on the device. We then touch on Android's storage encryption feature (introduced in
HoneyComb) and filesystem authentication using Linux's dm-verity (as introduced in KitKat).

Last, but in no way least, is a focus on device rooting, without which no discussion about
security would be complete. Rooting brings with it tremendous advantages to the power user (and is
one of the reasons Android's popularity has exploded in hacker and modder circles), but also woeful,
dire implications on application and system security. The two primary methods - boot-to-root and
"one-click" are detailed and contrasted.

207

---

**Page 74**

Android Internals::A Confectioner's Cookbook (Volume 1)

Threat Modeling Mobile Security

If one considers the evolution of hacking, a logical progression can be seen: At first, the main
targets were servers. It was much easier to hack into a server, a "sitting duck" in terms of being
always connected to the internet, than try to hack into a desktop, which only sporadically, if at all,
was ever connected - and even then, through a low bandwidth modem.

This changed with the proliferation of broadband connections, and the rise of local area
networks. Suddenly, millions of new potential targets emerged on the Internet. As desktop
machines, the security posture was off to a much weaker start than a server. Insecure defaults and
the overly user-friendly (and complex) operating system that was Windows provided a ripe breeding
ground for hackers, and brought on waves of worms and malware.

Attack vectors

Mobile devices, while similar in some respects to desktops, have an entirely different threat
landscape. Unlike the latter, their very mobility exposes them to far more risks, as they may be
accidentally misplaced, or deliberately stolen. This effectively negates the aspects of digital security
one could enforce on a desktop, by restrictring access at the lock and key (or keycard) level,
opening up a slew of attacks an adversary could try once physical access to a device is obtained.

But that, alas, is only half of it: Unlike desktops, mobile devices - being far more personal - are
more likely to contain personal user data, which makes them more lucrative a target for hacking.
The attack profile has also changed - rather than obtain full control of the device remotely (what
hackers call "pwning"), it often suffices to just get access to user data, and - using a likely always on
Internet connection - smuggle it out to a remote server.

The Rogue App

The primary attack vector on a mobile device is from within: That of a rogue application.
Users are eager to expand the functionality of their devices by installing more and more apps. But a
misbehaving or deliberately malicious app, could attempt to access the user's information, or even
take over phone functionality, for example by sending premium SMS messages for outrageous
prices. Generally, this is classified as local privilege escalation, as an application is already
installed and running on the local device, but with a restricted set of privileges, which is wishes to
elevate.

To prevent this, Android must treat all applications as suspect. By default, applications are given
a minimal set of permissions, but are otherwise restricted. The minimal set, however, does not
include anything which might be potentially sensitive - even if it is vital. Accessing the network, for
example, could be used maliciously to funnel out information from the device. For this reason, any
permission outside the minimal set must be explicitly requested by the application, in its manifest.
Each application is given its own UID, which isolates it from others, and - needless to say - root
access for applications is out of the question.

Android took a step up in application restrictions in Jellybean, with the introduction of SELinux,
a mandatory access control framework which effectively sandboxes all processes except the very
trusted ones. In Android L, the frameworks have also been extended to support package
restrictions.

That, however, is not enough - Android must also protect jtse/f, as it is likely that a malicious
application could try - within the limited subset of permissions it does have - to attack vulnerable
components of the operating system which houses it. This is not without precedent. It's possible to
exploit such vulnerabilities and trick more privileged components of the operating system -
particularly those running as root - to perform an operation on behalf of the application. Due to the
vast amount of code in the Android frameworks, and even more code in the underlying Linux kernel,
this is a serious threat. Most past vulnerabilities have in fact done just that in order to elevate their
privilege.

208

---

**Page 75**

Chapter VIII: Security
The Rogue User

It's hard to think of the device user as an actual threat (although iOS certainly seems to do so).
The potential of device theft, however, makes it unclear as to just who the valid user is. The system
must therefore be secure at all times, especially when outside the user's reach.

The first line of defense is the lock screen, which must balance the need for strong
authentication credentials with an easy to use (and quick) unlock operation. After all, you wouldn't
want to type in a 20 character, case-sensitive password every time your screen blanks! It therefore
falls upon the user to decide what is "acceptable" security, in choosing the authentication
mechanism, as well as the timeout to enforce it.

Android introduced face unlock as a method for quick (albeit not too safe) unlock, and (in
Lollipop) has followed iOS with built-in support for fingerprint authentication as well. Lollipop also
brings unlocking via paired devices (over Bluetooth, when the paired device - usually an Android
Wear device) is near.

There is also the potential of a device being stolen, turned off, and rebooted. For this, Android
must ensure its boot process is secure. Otherwise, someone could override the boot loader and
restart the device in an alternate configuration, which could be less secure. This is why boot loaders
are often locked by default, and if unlocked - will first efface the entire /data partition.

Finally, the user's data should be encrypted - else a sophisticated attacker can simply pry it
open and access the raw flash storage. Android offered encryption as early as Honeycomb, but once
again trailed iOS as it only enabled it by default beginning with Lollipop. The encryption key must
not rest anywhere on the device, and be derived from the user's unlock code for maximum usability.

Remote Code Injection

Last, but not least (if all the above weren't bad enough), mobile devices are still subject to the
very same attack vector servers and desktops were - remote code injection. The same class of
vulnerabilities which plague desktop can also affect mobile devices, as attackers seek to target
devices over the Internet, either as random "drive-by" (malware spam or malicious banners), or
through targetted attacks (usually socially engineered email).

Webkit, which served as the basis for Android's browser and webviews, has proven to be an
inexhaustible font for vulnerabilities. These were often carried out by a combination of malforming
HTML, CSS, Javascript, or all of the above. Google has now moved to Chrome as the default
browser, but the potential of a vulnerability in such a frequently used code based is so great, that
Lollipop checks and automatically updates Chrome indepedently of the rest of the OS.

It's worth noting that code injection can also exist in the boot loader phase. Such a vulnerability
could offer the same effect as unlocking the bootloader - i.e. booting into any configuration desired -
but without effacing data, and thereby compromising the user's data.

The Android approach to security

In security, the union of two elements does not necessarily make them secure. Quite the
contrary, in fact, as it suffices that one of the elements contains a vulnerability, in order for the
entire system to be compromised. Android has learned this oh-so-well over its relatively short
existence, as its security has been broken time and time (and time) again, despite significant
improvements with each version. Sometimes, the vulnerability lay in Android itself, and other times
in the underlying Linux. It follows, therefore, that Android security must incorporate both worlds -
Linux and its own - and combine them together as efficiently and as securely as possible.

209

---

**Page 76**

Android Internals::A Confectioner's Cookbook (Volume 1)

Security at the Linux Level

Android builds a rich framework on top of the Linux substrate, but at its core, relies on Linux for
virtually all operations. The Linux inheritance also binds Android to use the same security features as
those offered by Linux - the permissions, capabilities, SELinux, and other low-level security
protections.

Linux Permissions

The security model of Linux is a direct port of the standard UN*X security model. This model,
which has remained largely unchanged since its inception some 40 years ago, provides the following
primitives:

e Every user has a numeric user id: The actual user name doesn't matter, though some
usernames are reserved for system users (which are designated the owners of configuration
files and directories). Two users may share the same user id, but this in effect means that, as
far as the system is concerned, this represents a single user with two username/password
combinations.

e Every user has a numeric primary group id: Much like the username, the group name
doesn't matter, and some GIDs are reserved for system use.

e Users may hold memberships in additional groups: Traditionally, additional group
memberships is maintained by the /etc/group file. It lists the group names, group ids, and any
members who are not already in a group by virtue of the primary GID.

e Permissions on file are granted for a specified user, group, and "other": This is the
familiar output of "1s -1", which maps the permissions (read, write or execute) to the user

and group, and the "rest of the world". Both files and directories follow this extremely limited
model, for which UN*X has been duly criticized. Because of its limitations, file access
requirements basically force the creation of specialized groups

e (Almost) everything in UN*X can be accessed as files: It thus follows that access to

system resources - named IPC objects, UNIX domain sockets, and devices - is a corrolary of
file permissions. In other words, since the resources have a filesystem representation they
can be chown/chgrp/chmoded just as files can be, and have the same type of permissions.

e UID 0 is omnipotent: Because of the way permission checks are implemented, "0"
effectively short circuits the checks and grants access to all files, or resource. What follows is
that uid 0 (the "root" user) wields power absolute over the system.

e SetUID or SetGID binaries allow assuming another uid (or joining another grou
during their execution: with no questions asked. Having execute permission to a Set[ug]id
binary will automatically bestow those special permissions. This mechanism, which rightfully
looks like a gaping design flaw, is actually a feature, used to work around privileged
operations, such as changing one's uid (su) or password (passwd). Such operations - by
definition - are only possible for uid 0, but can be enabled if the root user empowers specific
binaries (by chmod 4xxx and 2xxx, for SetUID and SetGID, respectively). As a precaution,
copying or moving the binaries will strip those bits.

Android takes the classic model - which it obtains for free from the underlying Linux system -
and naturally employs it, but offers a different, somewhat novel interpretation: In it, the "users" are
granted to individual applications, not human users. Suddenly, much in the same way as human
users sharing the same UN*X server were comparmentalized from one another, applications enjoy
(and are limited by) the same seclusion. A user cannot access another user's files, directories, or
processes - and this exact isolation enables applications to run alongside eachother, but with no
power to influence one another. This approach is quite unique to Android - iOS runs all applications
under one uid (mobile, or 501) and relies on kernel-enforced sandboxing to isolate applications from
one another.

210

---

**Page 77**

Chapter VIII: Security

When an application is installed for the first time, the PackageManager assigns it a unique user
id - which is understandably referred to as an application id. This id is taken from the range of
10000-90000, and bionic - the Android C runtime library - automatically maps this to a human
readable name - app_XXX or u_XXXX.

Android can't get rid of SetUID support entirely - because this requires recompilation of the
kernel and other modifications. Beginning with JB 4.3, however, no SetUID binaries are installed by
default, and the /data partition is mounted with the nosuid option.

System defined AIDs

Android maintains the lower range of user ids - 1000-9999 - exclusive for system use. Only a
subset of this range is actually used, and it is hardcoded in android filesystem config.h. Table 8-1
shows the UIDs defined and used by Android. Most of these are used as GIDs as well: By joining
secondary groups, system processes like system_server, adb, installd and others gain the
ability to access system files and devices, which are owned by these groups - a simple yet effective

strategy.
Table 8-1:: Android AIDs and their default holders

GID #define Members Permits
1002 |arD_ BLUETOOTH] system_server |Bluetooth configuration files
1003. |arp_GRAPHICS |system_server |/dev/graphics/fb0, the framebuffer
1004 Jarp_InpuT system_server |/dev/input/*, the device nodes for input devices.
1005 arp avpto system server /dev/eac, Or other audio device nodes

= - access /data/misc/audio, read /data/audio
1006 |ArD_ CAMERA system_server |Access to camera sockets
1007 |Jarp Loc system_server |/dev/log/*
1008 |arp_comPAss |system_server |Compass and location services
1009 arp mount system server /dev/socket/vold, on the other side of which is the VOLume

- — Daemon
1010 Jartp_wiFi system_server |WiFi Configuration files (/data/misc/wifi)
1011 |arp_aps (reserved) Reserved for ADBD. Owns /dev/android_adb.
1012 |arp INSTALL Jinstalld Owns some application data directories
1013 Jarp MEDIA mediaserver Access /data/misc/media, and media.* service access
1014 Jarp_pucP dheped neces thee | Orne tie
1015 |artp_spcARD_RW Group owner of emulated SDCard
1016 |arp_vPN mtpd /data/misc/vpn, /dev/ppp

racooon

1017 ‘|arp_KEYSTORE |keystore Access /data/misc/keystore (system keystore)
1018 AID_USB system_server |USB Devices
1019 Jarp_ Drm Access to /data/drm
1020 |arp_MpDNSR mdnsd Multicast DNS and service discovery
1021 arp cps Access /data/misc/location
1023 |AID_MEDIA_RW |sdcard Group owner of /data/media and real SDCard
1024 |arp_mTp MTP USB driver access (not related to mtpd)

211

---

**Page 78**

Android Internals::A Confectioner's Cookbook (Volume 1)

Table 8-1 (cont)::

Android AIDs and their default holders

1026]arp_DRMRPC DRM RPC

1027} arp nec com.android.nfe venviee woke support: /data/nfc, and nfc
1028]artpD_SDCARD_R external storage read access

1029]}arp cLAT CLAT (IPv6/IPv4)

1030]arp Loop_RADIO Loop Radio devices

1031]artD_MEDIA_DRM DRM plugins. Access to /data/mediadrm.

1032] AID_PACKAGE_INFO Package information metadata

1033]aID SDcARD PICS PICS folder of SD Card

1034]arp_sDcARD_AV Audio/Video folders of SD Card
1035]arD_SDCARD_ALL All SDCard folders

Android system properties also rely on UIDs for access control - init's property_service limits
access to several property namespaces, as was shown in Chapter 4. It likewise falls on the
servicemanager, as the crux of all IPC, to provide basic security. Though the Binder eventually
provides security through a uid/pid model, servicemanager can restrict the lookup of well known
service names to given uids, though uid 0 or SYSTEM are always allowed to register. Up to and
including KitKat, this was in a hard-coded allowed array, as shown in Listing 8-1:

Listing 8-1: Hard-coded service permissions (from service _manager.c) on KK

/* TODO:
* These should come from a config file or perhaps be

* based on some namespace rules of some sort (media
* uid can register media.*, etc)
ef
static struct {
unsigned uid;
const char *name;
} allowed[] = {
{ AID MEDIA, "media.audio flinger" },
{ AID_MEDIA, "media.log" },
{ AID MEDIA, "media.player" },
{ AID_MEDIA, "media.camera" },
{ AID MEDIA, "media.audio policy" },
{ AID_DRM, "drm.drmManager" },
{ AID_NFC, Tee" jh,
{ AID BLUETOOTH, "bluetooth" },
{ AID_RADIO, "radio.phone" },
{ AID_RADIO, "radio.sms" },
{ AID_RADIO, "radio.phonesubinfo" },
{ AID RADIO, "radio.simphonebook" },
/* TODO: remove after phone services are updated: */
{ AID_RADIO, "phone" },
{ AID_RADIO, "sip" },
{ AID_RADIO, "isms" },
{ AID_RADIO, "iphonesubinfo" },
{ AID_RADIO, "simphonebook" },
{ AID_MEDIA, "common_time.clock" },
{ AID_MEDIA, "common_time.config" },
{

AID_KEYSTORE, "android.security.keystore" }

i

J] vevvvnee
int svc_can_register(unsigned uid, uint1l6_t *name)
{
unsigned n;
if ((uid == 0) || (uid == AID SYSTEM)) return 1;
for (n = 0; n < sizeof(allowed) / sizeof (allowed[0]); n++)
if ((uid == allowed[n] .uid) && strléeq(name, allowed [n] .name) )
return 1;
return 0;

212

---

**Page 79**

Chapter VIII: Security

With the introduction of SE-Linux, and the slow but steady migration of Android to it, the hard-
coded method has been finally abandoned, in favor of integration with an SE-Linux policy, much in
the same way as init's properties have. At any rate, it's important to note this is but one layer of
security: servicemanager refuses to allow untrusted AIDs to register well Known names. As we
discuss later, the Binder allows both client and server to perform additional permission checks, and
an additional layer of Dalvik-level permissions is also employed.

Paranoid Android GIDs

Android GIDs of 3000 through 3999 are also recognized by the kernel, when the
CONFIG PARANOID ANDROID is set. This restricts all aspects of networking access to these GIDs
only, by enforcing additional gid checks in the kernel socket handling code. Note that netd
overrides these settings, because it is running as root. Table 8-2 shows the known network ids

Table 8-2: Android Network-related AIDs and their holders

GID #define Members Permits

3001 |arp_ BT ADMIN system_server Creation of AF_BLUETOOTH sockets

3002 JarD_NET_BT system_server Creation of sco, rfcomm, or I2cap sockets

3003. Jatp NET INET system server /dev/socket/dnsproxyd, and AF_INET[6] (IPv4,
iin - IPv6) sockets

3004 |arp nET RaW eRe Create raw (non TCP/UDP or multicast) sockets

3005 |AID_ NET ADMIN racoon, mtpd Configure interfaces and routing tables

3006 |AID_NET_BW_STATS|system_server Reading bandwidth statistics accounting

3007 AID NET BW ACCT |system_server Modifying bandwidth statistics accounting

Isolated Services

As of Jelly Bean (4.1) Android introduces the notion of isolated services. This feature is a form
of compartmentalization (similar to iOS's XPC) which enables an application to run its services in
complete separation - in a different process, with a separate UID. Isolated services use the UID
range of 99000 through 99999 (AID _ISOLATED START through END), and the servicemanager
will deny them any request. As a consequence, they cannot lookup any system services, and are
effectively limited to in memory operations. This is primarily useful for applications such as web
browsers, and indeed Chrome is a prime example of using this mechanism. As shown in output 8-1,
isolated services are marked as uU##_i¥##:

Output 8-1: Chrome's isolated services

shell@htc | :/$ ps _|_grep chrome
u0_all4 384 1178728 118528 ff£ffffff 4007941c S com.android.chrome
u0_id ) 384 1283624 89788 ffffffff 4007941c com.android.chrome:sandboxed_proce

morpheus@Forge (/tmp)$S /aapt d xmltree Chrome.apk AndroidManifest.xml

"org.chromium. content .app.SandboxedProcessService0o"
com.google.android.apps.chrome.permission.CHILD_ SERVICE"
7pe 0x12) 0x0

) ndboxed_pro Oo"
x010103a9)=(type 0x1 xffffFfffFt

213

---

**Page 80**

Android Internals::A Confectioner's Cookbook (Volume 1)

Root-owned processes

As with Linux, the root user - uid 0 - is still just as omnipotent - but far from omnipresent: Its
use is limited to the absolute bare minimum, and that minimum is shrinking from one Android
release to another. Quite a few previous Android exploits targetted root-owned processes (with vold
being a perennial favorite), and the hope is that by reducing their number, the attack surface could
be greatly reduced. The installd is an example of such a process, whose root privileges have
been removed beginning with JellyBean.

It is likely impossible to remove all root owned processes: At the very least, init needs to retain
root capabilities, as does Zygote (whose fork() assume different uids, something only uid 0 can do).
You can see the root owned processes on your device by typing

ps | grep *root | grep -v "2"

(The grep -v ignores kernel threads, whose PPID is 2).

Table 8-3 shows the services which still run as root by default in KitKat (but note your device
may have more, as added by the device vendor)

Table 8-3: Android services still running as root

Service Rationale

Somebody has to maintain root privileges in the system and launch others - might as well
be PID 1

ueventd (init) | Minimal operation

init

healthd Minimal operation

Requires setuid() to change into AID when loading APKs, retains capabilities for
system_server

zygote[64]

Requires root privileges to use pt race (2), in order to read process memory when

debugger[64] generating tombstones

Developers may need legitimate root access;
adb system trusts ADB to immediately drop privileges to she11 if ro.debuggable is 0 or
ro.secure IS 1

vold [Un/]Mounting filesystems, and more.

netd Configuring interfaces, assigning IPs, DHCP and more

As stated back in Chapter 2, the vendor binaries greatly increase the attack surface of Android,
especially when they are run as root. What exacerbates the matter is that, whereas the AOSP
binaries remain open source and therefore easy to analyze for security by all, the vendor binaries
are closed source - and some vendors sacrifice security in favor of functionality. When you hear of a
specific vulnerability in a device (e.g. HTC One M8), rather than a version of Android, it is very likely
the cause lies within a vendor binary.

Eventually, it is expected that Android will leave only those services which absolutely must
have root, and others will follow in the steps of install1d. To do so, Android will have to increase
its usage of another important Linux security feature - Capabilities.

214

---

**Page 81**

Chapter VIII: Security

Linux Capabilities

Originally part of the POSIX.1e draft (and thus meant to be incorporated as a standard for all
UN*X), capabilities were an early adoption into the 2.2 line of kernels. Though the POSIX draft was
eventually withdrawn, capabilties remained implemented in Linux, and have since been expanded
and improved on. Distributions of Linux don't make use of capabilities all that often, but Android
makes extensive use of them.

The idea behind capabilities is to break the "all-or-nothing" model of the root user: The root
user is fully omnipotent, whereas all other users are, effectively, impotent. Because of this, if a user
needs to perform some privileged operation, the only standard solution is to resort to SetUID -
become uid 0, for the scope of the operation, then yield superuser privileges, and revert to a non-
privileged user. This holds true for even relatively simple operations: Setting the system time,
binding privileged (< 1024) network ports, mounting certain filesystems, and more. As a result,
UN*X systems traditionally contained a very large number of SetUID binaries.

If a SetUID binary can be trusted, then - in theory - the model should work. In practice,
however, SetUID poses inherent security risks: If a SetUID binary is somehow exploited, it could be
tricked into compromising root. Common tricks include symlinks and race conditions (diverting the
binary to overwrite system configuration files), and code injection (forcing the binary to execute a
root shell - hence the term "shellcode" for injected code).

Capabilities offer a solution to this problem, by "slicing up" the powers of root into distinct
areas, each represented by a bit in a bitmask, and allowing or restricting privileged operations in
these areas only, by toggling the bitmask. This makes them an implementation of the principle of
least privilege, a tenet of security which dictates that an application or user must not be given any
more rights than are absolutely required for its normal operation. You can see a logical view of
capabilities in Figure 8-1:

Figure 8-1: A logical representation of capabilities

“V7,
opm

215

---

**Page 82**

Android Internals::A Confectioner's Cookbook (Volume 1)

Restricting a subset of allowed privileges to only those absolutely required, while revoking the
rest, increases security significantly. Even if a given application or user ends up being malicious (or
cajoled to the dark path by code injection), its scope of damage is compartmentalized. Capabilities
are like a sandbox, allowing only those operations which an app, by design, requires - while at the
same time preventing it from running amuck and compromising system security. In fact, a nice side
effect of capabities is that they can be used to restrict the root user itself, in cases where the user
behind the uid is not fully trustworthy.

init still starts most of Android's server processes as root, and these processes have the full
capabilities bitmask (OxffffffffffffFFLL£) as they launch. Before these processes actually do
anything, however, they drop their privileges, and retain only the capabilities they need. A good
example of adhering to the principle of least privilege can be seen in installd, which makes sure
to drop all but the privileges it needs for package installation:

Listing 8-2: Installd's usage of capabilities

static void drop privileges() {

// Ask the kernel to retain capabilities, since we setgid/setuid next
if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
ALOGE ("prctl1(PR_SET_KEEPCAPS) failed: %s\n", strerror (errno) ) ;
exit (1);

}

// Switch to gid 1012

if (setgid(AID_INSTALL) < 0) {
ALOGE("setgid() can't drop privileges; exiting.\n");
exit (1);

}

// Switch to uid 1012

if (setuid(AID_INSTALL) < 0) {
ALOGE ("Setuid() can't drop privileges; exiting.\n") ;
exit (1);

}

struct __user_cap_header_struct capheader;
struct __user_ cap data_struct capdata[2] ;

memset (&capheader, 0, sizeof (capheader) ) ;

memset (&capdata, 0, sizeof (capdata) ) ;
capheader.version = _LINUX_CAPABILITY_VERSION_3;
capheader.pid = 0;

// Request CAP_DAC_ OVERRIDE to bypass directory permissions

// Request CAP_CHOWN to change ownership of files and directories

// Request CAP_SET[UG]ID to change identity
capdata[CAP_TO_INDEX(CAP_DAC_OVERRIDE)].permitted |= CAP_TO_MASK(CAP_DAC_OVERRIDE
capdata[CAP_TO_INDEX (CAP_CHOWN) ] .permitted |= CAP_TO_MASK(CAP_CHOWN) ;
capdata[CAP_TO_INDEX(CAP_SETUID)] .permitted |= CAP_TO_MASK(CAP_SETUID) ;
capdata[CAP_TO_INDEX(CAP_SETGID)] .permitted |= CAP_TO_MASK(CAP_SETGID) ;

capdata[0].effective = capdata[0] .permitted;
capdata[1].effective = capdata[1] .permitted;
capdata[0] .inheritable 0
capdata[1] .inheritable 0

i
i

if (capset (&capheader, &capdata[0]) < 0)
{ ALOGE("capset failed: %s\n", strerror(errno)); exit(1); }

The heaviest user of capabilties is, unsurprisingly, system_server, since it is a system
owned process, but still needs root privileges for many of its normal operations. Table 8-4 shows the
Linux capabilities, and the Android processes known to use them:

216

---

**Page 83**

Chapter VIII: Security

Table 8-4: Linux capabilities used by Android processes

capability #define Users Permits
0x01 CAP_CHOWN installd Change file and group ownership
0x02 CAP DAC OVERRIDE installa Override Discretionary Access Control on

— files/dirs

0x20 CAP_KILL system_server |Kill processes not belonging to the same uid
0x40 CAP_SETGID installd allow setuid(2), seteuid(2) and setfsuid(2)
0x80 CAP_SETUID installa allow setgid(2) and setgroups(2)
0x400 CAP_NET BIND SERVICE|system_server |Bind local ports at under 1024
0x800 CAP_NET_BROADCAST system_server | Broadcasting/Multicasting
0x1000 CAP NET ADMIN system_server | Interface configuration, Routing Tables, etc.
0x2000 CAP_NET_RAW system_server]|Raw sockets
0x10000 CAP_SYS MODULE system_server | Insert/remove module into kernel
0x800000 CAP_SYS_ NICE system_server | Set process priority and affinity
0x1000000 CAP_SYS_RESOURCE system_server | Set resource limits for processes
0x2000000 CAP_SYS_ TIME system_server | Set real-time clock
0x4000000 CAP_SYS TTY_CONFIG |system_server|Configure/Hangup tty devices
0x400000000 CAP_SYSLOG dumpstate Configure kernel ring buffer log (dmesg)

Note, that table 8-4 provides a limited (albeit large) subset of the Linux capabilities. It is likely
that over the evolution of both Linux and Android more capabilities will be added. The following
experiment demonstrates how you can see capabilities used by processes:

Experiment: Viewing capabilities and group memberships

You can easily view system_server's capabilities and group memberships (or those of any
other process, for that matter), by looking at /proc/${PID}/status, replacing ${PID} with the pid of
the process in question:

Output 8-2: Viewing system_server's capabilities and group memberships

eneric:/ # cat /proc/S${SS PID}/status

™m. er

TracerPid:
Uid: 1000

Gid: 1000

003 1004 1005 1006 1007 1008 1009 1010 1018 1032 3001 3002 3003 3006 3007

In the above, you can see four bitmasks for capabilities: Those inheritable by child process,
those potentially permitted for this process, those actively in effect (as in, permitted and also
explicitly required by the process), and the bounding set. The bounding set (added in Linux
2.6.25) is a bitmask which limits the usage of capset (2) ).

217

---

**Page 84**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Viewing capabilities and group memberships (cont. )

By looking over PIDs in /proc, you can single out the processes which use capabilities. This requires a bit of
shell scripting, as shown in the following output:

Output 8-3: Processes with capabilities

m8wl:/proc # for p in [0-9]*; \
do CAP="grep CapPrm $p/status |_\
grep -v -v ffffff IAN

grep -v 0000000000000"; \ # Rule out incapable

if [L_!  -z $CAP ]]; then \
grep Name $p/status;
echo PID $p - SCAP;
fi; \
done
Name: system server
ID 13662 - CapPrm: 0000000007813c20
Name: wpa_supplicant
PID 13907 - CapPrm: 0000000000003000

Name: rild

PID 368 - CapPrm:
Name: netmgrd
PID 375 - CapPrm:
Name: installd
PID 387 - CapPrm:
Name: dumpstate
PID 389 - CapPrm:
Name: dumpstate
PID 390 - CapPrm:
Name: qseecomd
PID 398 - CapPrm:

Name: qseecomd
PID 510 - CapPrm:

0000000000003000
0000000000003000
00000000000000c3
0000000400000000
0000000400000000
0000000000222000

0000000000222000

As the above shows, the capabilities are in line with Table 8-4. Note that some vendors (above, HTC) may
add their own processes (above, qseecomd) with additional capabilities.

Beginning with JB (4.3), Zygote calls prct1(PR_CAPBSET DROP) and
prctl (PR_SET_NO_NEW_PRIVS), to ensure that no further capabilities can be added to its child
processes (i.e. the user apps). It is likely that, going forward, vold and netd will both drop their
privileges and rely on capabilities, rather than retain their root privileges. This is especially important
considering vold's history of vulnerabilities.

218

---

**Page 85**

Chapter VIII: Security

SELinux

SELinux - Security Enhanced Linux - marks a step further in the evolution
of Linux beyond standard UN*X. Originally developed by the NSA, Figure 8-2: The SELinux logo
SELinux is a set of patches which have long since been incorporated into
the mainline kernel, with the aim of providing a Mandatory Access
Control (MAC) framework, which can restrict operations to a predefined
policy. As with capabilities, SELinux implements the principle of least
privilege, but with much finer granularity. This greatly augments the
security posture of a system, by preventing processes from operating
outside strictly defined operational bounds. So long as the process is
well behaving, this should pose no problem. If the process misbehaves,
however (as most often is the case of malware, or the result of code injection), SELinux will block
any operation which exceeds those bounds. The approach is very similar to iOS's sandbox (which
builds on the TrustedBSD MAC Framework), though the implementation is quite different.

Though long included in Linux (and, like capabilities, not always implemented by default),
SELinux was introduced into Android with JellyBean (4.3). The initial introduction was gentle -
setting SELinux in permissive mode, wherein any violations of the policy are merely audited. With
KitKat (4.4), however, SELinux now defaults to enforcing mode for several of Android's services
(specifically, installd, netd, vold and zygote), though still permissive for all other processes.
In general, it is considered a good practice to use the per-domain permissive mode, in order to test
a policy before setting it to enforcing, and it is likely that enforcement will expand with the next
version of Android.

SELinux's port to Android - commonly referred to as SEAndroid - was first described in a paper'#
and a presentation’> by Smalley and Craig of the NSA (who have followed up on SEAndroid with an
excellent presentation in the 2014 Android Builders Summit**). Google provides basic documentation
in the Android Source site?. Of the mainline Linux distributions RedHat has been an early adopter,

and provides a comprehensive guide’.

SEAndroid follows the same principle of the original, but extends it to accommodate Android
specific features - such as system properties, and (naturally) the Binder (via kernel hooks). Samsung
further extends SEAndroid, and uses it as a foundation for their "KNOX" secure platform (currently in
v2.0). KNOX (referred to by some as "obKNOXious" :-) boasts a stronger security policy, enforcing
and confining all processes (except init and the kernel threads). In the following discussion,
"SELinux" refers to those features found in both Linux and Android, whereas "SEAndroid" refers only
to the latter.

The main principle of SELinux (and, in fact, most MAC frameworks) is that of /abeling. A label
assigns a type to a resource (object), and a security domain for a process (subject). SELinux can
then enforce so as to allow only processes in the same domain (likewise labeled) to access the
resource (Some MAC Frameworks go as far as to make resources with different labels invisible,
somewhat akin to the Linux concept of namespaces, although SELinux does not go that far).
Depending on the policy, domains can also be made confined, so that processes cannot access any
resource but those allowed. The policy enforcement is performed independently of other layers of
permissions (e.g. file ACLs). The policy may also allow relabeling for some labels (relabelto and
relabelfrom, also called a domain transition) in some cases, which is a necessary requirement if a
trusted process (e.g. Zygote) spawns an untrusted one (virtually any user application).

An SELinux label is merely a 4-tuple, formatted as a string of the form
user: role: type: level. All processes with the same label (i.e. in the same domain) are
equivalent. SEAndroid (presently) only defines the type - i.e. the label is always in the form
u:r:domain: so. As of KitKat, the SEAndroid policy defines individual domains for all daemons (i.e.
each daemon gets its own permissions and security profiles), along with the domains shown in table
8-5, for application classes.

219

---

**Page 86**

Android Internals::A Confectioner's Cookbook (Volume 1)

Table 8-5: The application class domains in Android 4.4

Label (domain) Apps Restrictions

Reserved for kernel

threads Unconfined (God Mode)

u:r:kernel:s0

Previously connected anonymous UNIX sockets,

:v:isolated :s0 |Isolated processes °
BEER BORAEES EPP ES P read/write

u:r:media_app:s0 signed with media key

u:r:platform_app:so |signed with platform key

- ; Allowed to access network
u:r:shared_app:s0 signed with shared key

u:r:release_app:so0 {signed with release key

u:r:untrusted_app:so [All other Access ASEC, SDCard, TCP/UDP sockets, PTYs

The keys referred to in table 8-5 are defined in /system/etc/security/mac_permissions.xml, which
is part of the middleware MAC (MMAC) implementation: The Package Manager recognizes the
keys used for signing apps, and labels the applications accordingly (using a call to
SELinuxMMAC.assignSeinfoValue. This is done during package scanning (part of the package
installation, as described in Volume II). Note the term middleware here applies to labeling
performed strictly in user mode by the Android system components.

All the _app domains inherit from the base appdomain, which allows the basic application
profile, including actions such as using the binder, communicating with zygote, sufraceflinger, etc.
You can find the type enforcement (.te) files, which contain the detailed definitions for all domains,
in the AOSP's external/sepolicy directory. The syntax used in those files is a mixture of keywords and
macros (from temacros), which allow or deny operations in the domain, as shown in Listing 8-3:

Listing 8-3: Sample te file (debuggerd.te)

# debugger interface

type debuggerd, domain;

permissive debuggerd;

type debuggerd_exec, exec_type, file type;

unconfined_domain (debuggerd) Leaves debuggerd unconfined, at present}
relabelto_domain (debuggerd) Allow domain transition to this domain]
allow debuggerd tombstone _data_file:dir relabelto; |# For tombstone files|

init_daemon_domain (debuggerd) force automatic transition when init spawns ug}

The files in external/sepolicy form the baseline, which all devices are meant to automatically
inherit from. Rather than modify them, vendors are encouraged to add four specific variables in
their BoardConfig.mk file, specifying BOARD _SEPOLICY_[REPLACE|UNION| IGNORE], to override,
add or omit files from the policy, and BOARD_SEPOLICY_DIRS to provide the search path for the
directories containing their files. This mitigates the risk of an accidental policy change due to file
error, which may result in security holes. The directory also contains the mac_permissions.xml
template, which is populated with keys in keys.conf.

The stock type enforcement files are all concatenated and compiled into the resulting /sepolicy
file, which is a binary file placed on the root file system. Doing so offers further security, because
the root filesystem is mounted from the initramfs, which is itself part of the boot img, that is
digitally signed (and therefore hopefully tamperproof). The compilation is performed merely as an
optimization, and the resulting file can be easily decompiled, as is shown in the experiment sec-
dispol. The binary policy file can be loaded through /sys/fs/selinux (though init most commonly does
so through 1ibselinux.so).

220

---

**Page 87**

Chapter VIII: Security

Experiment: Decompiling an Android /sepolicy file

If you have a Linux host, decompiling an /sepolicy can be performed with the sedispol command,
which is part of the checkpolicy package. Assuming Fedora or a similar derivative, this first involves
getting the package, if you don't already have it:

Output 8-4: Obtaining the checkpolicy package

root@Forge (~)# yum_install checkpolicy

Loaded plugins: langpacks, refresh-packagekit

--> Running transaction check

---> Package checkpolicy.x86_64 0:2.1.12-3.fc19 will be installed
--> Finished Dependency Resolution

Installed:

checkpolicy.x86_64 0:2.1.12-3.fc19
root@Forge
/usr/bin/checkmod
/usr/bin/checkpolicy
/usr/bin/sedismod
/usr/bin/sedispol # This is the policy disassembler
/usr/share/man/man8/checkmodule.8.gz
/usr/share/man/man8/checkpolicy.8.gz

Once you have the command, all you need is to transfer the policy to the host, and start examining it
(the command is an interactive one). Though the policy is usually the one defined in /sepolicy, you can
get the actively loaded policy through sysfs, as well. The /sys/fs/selinux/ directory will contain many
interesting entries used for configuring (and potentially disabling) SELinux, of which one is the actively
loaded policy. This will require you to do something similar to the following:

Output 8-5: Decompiling/Disassembling the active policy

root@htc_m8wl:/ # 1s -l /sys/fs/selinux/policy /sepolicy

-r-- -- root root 74982 1970-01-01 01:00 policy

-rw-r--r-- root root 74982 1970-01-01 01:00 sepolicy

root@htc_m8wl:/ # ep /sys/fs/selinux/policy /data/local/tmp

root@htc_m8wl:/ # chmod 666 /data/local/tmp/sepolicy

#

# Back on the host (as any user)

#

morpheus@Forge (~)$ adb pull /data/local/tmp/sepolicy

2750 KB/s (74982 bytes in 0.026s)

morpheus@Forge (~)$ sedispol sepolicy

Reading policy...

libsepol.policydb_index_others: security: 1 users, 2 roles, 287 types, 1 bools
libsepol.policydb_index_others: security: 1 sens, 1024 cats
libsepol.policydb_index_others: security: 84 classes, 1333 rules, 1 cond rules
binary policy file loaded

Select a command:
1) display unconditional AVTAB

Command ('m' for menu): 1
allow qemud installd : udp_socket { ioctl read write create getattr setattr lock relabelfrom
relabelto append bind connect listen accept getopt setopt shutdown recvfrom sendto recv_msg
send_msg name_bind node_bind };
allow system installd : udp_socket { ioctl read write create getattr setattr lock relabelfrom
relabelto append bind connect listen accept getopt setopt shutdown recvfrom sendto recv_msg
send_msg name_bind node_bind };
allow keystore ctl_dumpstate_prop : property_service { set };
allow keystore ping : peer { recv };
. # Probably more output than your terminal can buffer - consider "f" for file output..

What remains, then, is to define the process of assigning the labels to resources, through
contexts. The resources recognized by SELinux are Linux file objects (including sockets, device
nodes, pipes, and other objects with a file representation), and SEAndroid extends this further to
allow for properties.

221

---

**Page 88**

Android Internals::A Confectioner's Cookbook (Volume 1)

Application Contexts

The /seapp_contexts file provides a mapping of applications (in the form of UIDs) to domains.
This is used to label processes based on the UID, and the seinfo field (as set by the package
manager, according to the package signature as it correlates with
/system/etc/security/mac_permissions.xml). You can see the labeling of processes with the toolbox's
ps -Z!

Output 8-6: SELinux process contexts with ps -Z

:r:platform_app:s0 u0_a42 7343 7129 com.android.systemui
:platform_app:s0 smartcard 7717 7129 org.simalliance.openmobileapi.service:remote
:platform_app:s0 u0_a42 30131 7129 com.android.systemui:recentapp
:platform_app:s0 fm_radio 30405 7129 com.htc.fmservice

Compare with seapp contexts

shell@htc_m8wl:/ $ grep platform app /seapp contexts

user=_app seinfo=platform domain=platform_app type=platform_app_data_file

user=smartcard seinfo=platform domain=platform_app type=platform_app_data_file # PID 7717
user=felicarwsapp seinfo=platform domain=platform_app type=platform_app_data_file
user=irda seinfo=platform domain=platform_app type=platform_app_data_file

user=fm_radio seinfo=platform domain=platform_app type=platform_app_data_file # PID 30405

File Contexts

SE-Linux can associates every file with a security context. The /file_contexts file provides all the
contexts for protected files, and the -Z switch of toolbox's 1s can display them, as shown in the
following:

Output 8-7: SELinux file contexts with ps -Z

shell@htc_m8wl:/ $ 1s -% /dev_|_ grep video device

drwxr-xr-x root root :object_r:video_device: video

crw-rw---- system camera :object_r:video_dev : videod

crw-rw---- system camera :object_r:video_device: videol

crw-rw---- system camera :object_r:video_device: video2

crw-rw---- system camera :object_r:video_device: video3

crw-rw---- system camera :object_r:video_device: video32

crw-rw---- system camera :object_r:video_device: video33

crw-rw---- system camera :object_r:video_device: video34

crw-rw---- system camera :object_r:video_device: video35

crw-rw---- system camera ject_r:video_device: video38

crw-rw---- system camera :object_r:video_device: video39

#

# Compare with /file_contexts definitions

#

shell@htc_m8wl:/ $ grep video device /file contexts

/dev/nvhdcpl u:object_r:video_device:s0 # Left over from the external/sepolicy/file contexts,
/dev/tegra.* u:object_r:video_device:s0 # even though this is not an NVidia device
/dev/video [0-9] * u:object_r:video_device:s0 # note regular expressions gets all the above

Property Contexts

As discussed in Chapter 4, init's property service restricts access to certain property
namespaces by a hard coded uid table. This is a very rigid mechanism, and hardly scalable as new
properties and namespaces are added in between Android releases.

Since SELinux already provides the notion of execution contexts, it is trivial to extend them to
properties, as well. As of JellyBean, /init protects access to properties by a check_mac_perms ()
boolean. The function loads the property contexts from two files - /data/security/property_contexts
(when present), and /property_contexts.

222

---

**Page 89**

Chapter VIII: Security

Output 8-8: SELinux Property contexts

shell@htc_m8wl:/ S$ cat /property contexts

#line 1 "external/sepolicy/property_contexts"
HEHEHE HEH HHH HH HHH HHH HHH HH

# property service keys

#

#

net.rmnet0 :object_r:radio_prop:s0

sys.usb.config :object_r

ril. :object_r:rild_pro

net.
dev.
runtime.
hw.

:object_r:system pro
:object_r:system_pro
:object_r:system
:object_r:system_prop
:object_r:system_pro
:object_r:powe
:object_r:system
:object_r:system_pr
:object_r:system_pr
:object_r:bluetoo

sys.
sys.powerctl
service.
wlan.

dhep.
bluetooth.

sececeereecee

debug. :object_r:shell_p
log. :object_r:shell_pro
service.adb. root :object

If you go back to Chapter 4, you'll see that the property contexts essentially mirror the
definitions in the table. The main difference, however, is that providing the contexts in an external
file provides a far more extensible way of changing and modifying properties - all without a need to
recompile /init.

init and toolbox commands

Recall from Chapter 4 that the Android /init has a rich variety of commands, which may be used
in its .rc files. With the introduction of SELinux, additional commands have been added to allow for
SELinux contexts. Toolbox has likewise been modified to allow SELinux modifications from the shell.
Table 8-6 shows these commands

Table 8-6: init and toolbox commands for SELinux

init Toolbox Usage

N/A getenforce Get SELinux Enforcement status

Set (change) SELinux context. Init uses

setcon SEcontext N/A
u:r:init:s0

t -nrR :
restorecon path restorecon [-nrRv] Restore SELinux context for path
pathname...

setenforce [0/1] setenforce Toggle SELinux enforcement on/off

[Enforcing|Permissive|1]|0]

setsebool name value|setsebool name value Toggle boolean value (0/false/off or 1/true/on)

Note you can achieve most of the functionality of the SELinux commands by accessing files in
/sys/fs/selinux (which is, in fact, what some of these commands do), though this would require both
root access and an unconfined domain. /init, which remains unconfined, can also relabel processes
(as it does for services with the seclabel option, and additionally provides the
selinux.reload_ policy property trigger to reload the policy. Disabling SELinux altogether can
be accomplished through /sys/fs/selinux/disable, or through the kernel command line argument
selinux=0.

223

---

**Page 90**

Android Internals::A Confectioner's Cookbook (Volume 1)

Other noteworthy features

Linux has some additional settings which Android enables, which aim to improve security by
hardening otherwise insecure defaults. This section discusses them briefly.

AT_SECURE

The Linux Kernel's ELF loader uses an auxilliary vector to provide metadata for the images it
loads. This vector can be accessed through the /proc filesystem (as /proc/pid/auxv. One of its entries,
AT_SECURE is set to a non-zero value for set[ug]id binaries, programs with capabilities, and
programs which force an SELinux domain traversal. In those cases, Bionic's linker
(/system/bin/linker) is configured to drop "unsafe" environment variables (a hard coded list in the
__is_unsafe_environment_variable function, in bionic/linker/linker_environ.cpp. Chief amongst the
variables are LD_LIBRARY_PATH and LD PRELOAD, a favorite technique for library injection.

Address Space Layout Randomization

Code injection attacks use the target process' address space as their playing field, and their
success often depends on intimate knowledge of its details - addresses, regions and protections.
This is because injection attacks either directly add code into an existing program, or subvert its
execution so as to jump to already existing regions. In both cases, knowledge of the layout is vital,
because jumping to an incorrect address will lead to a crash. Normally, since process launch
deterministically into a private address space, a hacker can (to paraphrase an old java motto)
"debug once, hack everywhere".

Address Space Layout Randomization (ASLR) attempts to make injection attacks harder by
introducing randomness - shuffling the layout of memory regions, making their addresses less
predictable. This increases the chance a targetted piece of code will be "shifted" in memory, and
basically trade a crash in place of compromise by malicious code - a lesser evil, by all counts.

Linux offers randomization capabilities through /proc/sys/kernel/randomize_va_space (or sysctl
kernel.randomize_va_space). The value "0" specifies no randomization, "1" specifies stack
randomization, and "2" specifies both stack and heap, which is the default. Executables can also be
compiled with the PIE (Position-Independent-Executable) option (the -pie switch), which is
mandatory as of Android L (defined as APP_PIE in the Android.mk files).

Experiment: Testing ASLR

To see the effects of ASLR, you can use the following shell script over /proc. The script
iterates over all processes, finds the location of libc.so in it (only the text section, as filtered by the
grep r-x), and displays it along with the PID if found:

Output 8-9: Showing the effects of ASLR

tc_m8wl:/# ed /proc
tc_m8wl:/proc # for x in [0-9]*; do \
lc="grep libc.so /proc/$x/maps|_grep r-x"~; \
if [[I_! -z "Sle" ]]; then echo $lc in PID $x; fi; \

done _|_so

400c6000-40111000 r-xp 00000000 b3:2e 1492 /system/lib/libc.so in PID 28686

0 0 0 b3:2 > -so in PID 9615
béde0000-b xp 0000C b 9 yste o in PID 7470
b6e5a000-b Or 0000 0 :2e 9 /s /lib/1i -so in PID 375

As the output shows, the library is often randomized, yet some processes still share the same
location for libc - those are the spawns of the zygote, which fork () to load a class, but does not
call exec () - and hence remains with the same address space layout.

224

---

**Page 91**

Chapter VIII: Security
Kernel-space ASLR has yet (at the time of writing) to make it into Android. Introduced for the
first time in iOS 6.0, it eventually made it into Linux with version 3.14 (which is actually the most
recent at the time these lines are being typed). It is quite likely to be introduced into Android with
the version to follow KitKat.

Kernel hardening

Unlike mainline Linux, Android kernels export no /proc/kcore by default, as this entry allows
kernel read-only memory access from user mode (by root). The /proc/kallsyms is still present in most
devices (and actually world readable by default), but protected by the kernel.kptr_restrict sysctl,
which is set by default to 2, to prevent any addresses from being displayed. Kernel ring-buffer
access (via the dmesg) is likewise protected by kernel.dmesg_restrict.

Stack protections

As sophisticated as attacks can get, they still (for the most part) rely on overwriting a function
pointer, which - when called - causes a subversion of the program flow. Not all programs use
function pointers, but all utilize the return address, which is stored on the stack during a function
call.

As a countermeasure to this, most modern compilers offer automatic stack protection, by
means of a canary. Like the proverbial canary in the coal mine, a stack canary is a random value
written to the stack upon function entry, and verified right before the function returns. If the value
cannot be verified, the stack is deemed corrupt, and the program voluntarily aborts, rather than
potential trigger malicious code.

This form of protection has been available in Android since its early days, with gcc's -fstack-
protector. Note that it does not provide a panacea, since code can still be injected via function
pointers aside from the return address (C++ methods make good candidates).

Data Execution Prevention

Code injection attacks rely on embedding malicious code inside input - whether direct from the
user or from other sources. Input, however, is data - and memory used for data (the heap and the
stack) can be flagged as non-executable. This complicates attacks somewhat, because just using the
classic trampoline technique (overwriting a pointer or the stack return address with the address of
the injected code) won't work if the injected code is in the data segment.

Unfortunately (for most), while making data non-executable complicates the simple attacks,
attacks have considerably evolved. The current counterattack is Return-Oriented-Programming
(ROP), a fairly old technique (introduced by Solar Designer in a '00 paper as return-to-libc), which
strings together "gadgets" of calls back into existing portions of code in the program, simulating
function calls on the stack. Because these are calls into code, there's nothing to make non-
executable, and thus the protection can be fairly reliably circumvented.

Compiler-level protections

All the above protections are, in a way, treating the symptoms, rather than the disease. At the
end of the day, the only proper ways to combat code injection attacks which exploit memory
corruption is to exercise defensive coding, which involves input validation and strict bounds checking
on memory operations. Newer versions of Android have taken that to heart, with the source
compiled with enhanced checks, most notably FORTIFY SOURCE and -Wformat-security,
which add additional checks on memory copying functions, and prevent format string attacks.

225

---

**Page 92**

Android Internals::A Confectioner's Cookbook (Volume I)

Security at the Dalvik Level

Dalvik Level Permissions

Working at the level of a virtual machine, rather than native code, brings with it tremendous
advantages for monitoring operations and enforcing security. At the native level, one would have to
monitor system calls for any significant resource access. The problem with system calls, however, is
that their granularity is inaccurate. File access is straightforward (open/read/write/close), but other
operations, (e.g. a DNS lookup) are a lot harder to monitor, as they involve multiple system calls.
Therein lies the advantage of the Virtual Machine - most operations are carried out by means of pre-
supplied packages and classes, and those come built-in with permission checks.

Android actually takes this a step further: Whereas in a normal Java class a malicious developer
could ostensibly import other classes, implement functionality from scratch or use JNI (to break out
of the VM), in order to avoid permission checks, though this is next to impossible in Android: The
user application is entirely powerless, devoid of all capabilities and permissions at the Linux level, so
any access to the underlying system resources should be blocked right there. In order to carry out
any operation which has an effect outside the scope of the application, one has to involve
system_server, by calling getSystemService().

While any app can freely invoke a call to system_server, none has access to its defined
permissions - which system_server will check. This check is performed outside the application's
process, so the application has no plausible avenue by means of which it may somehow obtain
those permissions, unless they were a priori assigned to it. The assignment is performed when the
application is loaded and installed - meaning that the user has been notified of the application's
requested permissions,(has hopefully read through the very long list), and approved them (again,
hopefully knowing the ramifications of hitting "OK")*. If the permission requested during runtime
has been revoked (for example, through the AppOps service or through pm revoke), a security
exception will be thrown (normally, this will crash the application, unless the developer braced for
such an exception, in which case it may handle the exception, usually popping up an explanation on
what permission was required, or at other times failing silently).

What follows is that the permissions themselves need no special data structures or complicated
metadata. A permission in Dalvik is nothing more than a simple constant value, which is granted to
an application in its manifest, as it declares it <uses-permission>. An application can likewise
define its own constants (as <permission> tags in the Manifest). When the Package Manager
installs an app, it adds the permissions of said app to the "permissions database", which is in effect
part of the package database, /data/system/packages.xml. This database contains a lot more valuable
information (including public keys) than just permissions (which is why it is discussed in detail in
Volume IT), but the pertinent portions of it are shown in Table 8-7:

Table 8-7: The elements pertaining to permissions in the package database
Element Contains

An array of tree items, specifying permission namespaces, and the packages which

permission-trees define them

An array of permission items, each of which defines:

® name - The permission constant name, as defined in its original permission
element

® package - The package which defined this permission (with "android" for SDK
permissions)

permissions . . _ .
@ protection - which defines the permission protection level and flags from the

PermissioniInfo Class. Permissions levels are 0 (PROTECTION NORMAL), 1

(. . DANGEROUS), 2 (.._ SIGNATURE) Or 3 (. .SIGNATURE_OR_SYSTEM), With flags
for system (0x10) and pEvELopment (0x20). Note the value is printed as a
decimal integer, when in fact it should be hexadecimal.

* - Android M finally fixes this naive and broken model, following iOS's design of enforcing permissions during runtime,
prompting the user during the action, with the help of an out-of-process entity (in iOS this is handled by the TCC daemon).

226

---

**Page 93**

Chapter VIII: Security

Table 8-7 (cont.): The elements pertaining to permissions in the package database
Element Contains

package Each installed application is identified by its name attribute (reverse DNS name of
package) and assigned an AID via the userra attribute. Specific permissions granted to
the application are listed as items in the <perms> child element.

shared-user |AIDs shared between two or more applications are specified by the userid attribute,
and once more specific permissions are granted - this time to the AID (i.e. all
applications sharing it) as items in the <perms> child element.

If you inspect the package database (as root), you will find that the <permissions> element
contains both custom permissions (i.e. those declared by installed Apps) and system ones. The built-
in system permissions, along with protected broadcasts, are specified in the
/system/framework/framework-res.apk, which can be examined using aapt, as shown in the following
output:

Qutput 8-10: Dumping the /system/framework/framework-res.apk from a Nexus 9

morpheus@Forge (~/tmp) % adb pull /system/framework/framework-res.apk
6343 KB/s (19250841 bytes in 2.963s)
morpheus@Forge (~/tmp) % aapt d xmltree framework-res.apk AndroidManifest.xml_ |_more
N: android=http://schemas.android.com/apk/res/android
E: manifest (line=20)
: android: sharedUserId(0x0101000b) ="android.uid.system" (Raw: "android.uid.system")
: android: versionCode (0x0101021b)=(type 0x10) 0x15
: android:versionName (0x0101021c) ="5.0-1573874" (Raw: "5.0-1573874")
: android: sharedUserLabel (0x01010261) x1040104 # link to resources.arsc
: package="android" (Raw: "android")
: coreApp=(type 0x12) 0xffffff£F£ (Raw: "true")
: uses-sdk (line=0)
A: android:minSdkVersion(0x0101020c)=(type 0x10) 0x15 # 21, For Android L
A: android:targetSdkVersion(0x01010270)=(type 0x10) 0x15 # 21, For Android L
E: eat-comment (line=27)
E: protected-broadcast (line=29)
A: android:name (0x01010003)="android.intent.action.SCREEN_OFF"
E: protected-broadcast (line=30)
A: android:name (0x01010003) ="android.intent.action.SCREEN_ON"

# Permission groups, as returned by pm list permission-groups
E: permission-group (line=315)
android: label (0x01010001) =@0x1040109 # For UI or pm.
android:icon(0x01010002 0x1080532 # For UI display
android:name (0x01010003) ="android.permission-group.MESSAGES"
android:priority(0x0101001c)=(type 0x10) 0x168
android: description (0x01010020) =@0x104010a # for pm list permissions -s
android:permissionGroupFlags (0x010103c5)=(type 0x11)0x1 # FLAG _PERSONAL_INFO
permission (line=323)
android: label (0x01010001) =@0x1040161
android:name (0x01010003) ="android.permission.SEND_SMS" # For UI or pm .. -s
android: protectionLevel (0x01010009)=(type 0x11) 0x1 # NORMAL (0), DANGEROUS(1), etc
android: permissionGroup (0x0101000a) ="android.permission-group.MESSAGES"
androi escription(0x01010020) =@0x1040162 # for pm list permissions -s
android:permissionFlags (0x010103c7)=(type 0x11) 0x1 # FLAG COSTS MONEY

PPP PPE

PPP PP pe

As the above shows, permission are bundled into groups, with flags” defined both at the group
level (through android. content .pm. PermissionGroupInfo) and at the individual level
(through android. content .pm.PermissionInfo). This bundling and categorizing comes in
handy for the power user, who is expected to use the pm upcall script to display or manage
permissions.

* - Make that "flaG", since at the present time only FLAG PERSONAL INFO (group) and FLAG COSTS MONEY (permission)
are used. But this scheme does allow for future extension

227

---

**Page 94**

Android Internals::A Confectioner's Cookbook (Volume 1)

Experiment: Using the pm command

You can use pm list permissions to display permissions, both of the Android
frameworks, and of third party applications. To do so, try:

Output 8-11: Listing permissions with pm

root@htc_m8wl:/# pm list permissions -f | more
All Permissions:
+ permission:android.permission.GET TOP ACTIVITY INFO
package:android
label:get current app info
description:Allows the holder to retrieve private information about the current applicatio
in the foreground of the screen.

protectionLevel :signature

. # Application declared permissions, as imported from their AndroidManifest.xml
permission:com. facebook.system.permission.READ NOTIFICATIONS

package:android

label :null

description:null

protectionLevel :signature

Other useful switches include -s (verbose human readable output in your locale), -g
(permission groups). The pm command can also be used to grant and revoke optional permissions
(pm [grant |revoke] PACKAGE PERMISSIONS) and even toggle permission enforcement (i.e.
pm set-permission-enforced PERMISSION [true] false] ). The full syntax of this
command, including some notable changes made for Android M, is explained in Volume II.

The AppOps service (detailed in Volume ITI) provided a powerful GUI by means of which users
could track and fine-grain tune application permission usage. The GUI has been removed as part
of KitKat's 4.4.2 "security update", but the service is alive and well. In fact, Lollipop introduces the
appops upcall script, which can be used to allow, deny, ignore or reset an application's
permissions. Unfortunately, the command line only allows a small subset of operations (android:
[coarse|fine|monitor] location and android:get_usage_stats and
android:activate_ vpn), but those could be extended to the full set of (presently) 48
operations by recompiling android. app.AppOpsManager. Note, however, that AppOps is
another layer on top of the permissions - and uses a separate database (/data/system/appops.xml).
This is shown in Output 8-12:

Output 8-12: Demonstrating the appops upcall script in L

shell@flounder:/ $ appops
usage: adb shell appops set <PACKAGE> <OP> <allow|ignore|deny|default> [--user <USER_ID>]
<PACKAGE> an Android package name.
<OP> an AppOps operation.
<USER_ID> the user id under which the package is installed. If --user is not
specified, the current user is assumed.
shell@flounder:/ $ appops set com.android.musicfx android:get usage stats allow
# To see changes reflected in the AppOps database, you need root:

shell@flounder:/ $ su

root@flounder:/ # cat /data/system/appops.xml | grep -A 4 musicfx

<pkg n="com.android.musicfx">

<uid n="10014" p="true">

<op n="0" />

<op n="43" m="0" /> # android.apps.AppOpsManager.OP_GET_USAGE_STATS = 43
</uid>

228

---

**Page 95**

Chapter VIII: Security

Mapping permissions to Linux UIDs

The /system/etc/permissions/platform.xml file acts as a "glue" between Dalvik level permissions
and those of Linux. The file is included in the AOSP sources, and is well documented so that vendors
can (carefully) add any specific permissions or AIDs. The mapping works both ways - that is, a given
<permission> can be set to grant membership to a <group>, and vice versa by using <assign-
permissions to a given named permission to a uid. Listing 8-4 shows a sample of this file:

Listing 8-4: An example /system/etc/permissions/platform.xml file

<!-- This file is used to define the mappings between lower-level system
user and group IDs and the higher-level permission names managed
by the platform.

Be VERY careful when editing this file! Mistakes made here can open
big security holes.

-->

<permissions>

<!-- The following tags are associating low-level group IDs with
permission names. By specifying such a mapping, you are saying
that any application process granted the given permission will
also be running with the given group ID attached to its process,
so it can perform any filesystem (read, write, execute) operations
allowed for that group. -->

<permission name="android.permission.BLUETOOTH_ADMIN">
<group gid="net_bt_admin" />
</permission>

<!-- The following tags are assigning high-level permissions to specific
user IDs. These are used to allow specific core system users to
perform the given operations with the higher-level framework. For
example, we give a wide variety of permissions to the shell user
since that is the user the adb shell runs under and developers and
others should have a fairly open environment in which to
interact with the system. -->

<assign-permission name="android.permission.MODIFY_AUDIO_SETTINGS" uid="media"/>
<!-- This is a list of all the libraries available for application
code to link against. -->

<library name="android.test.runner"
file="/system/framework/android.test.runner.jar" />

</permissions>

If you check the /system/etc/permissions/ directory on your device, you will likely find several
more XML files - android.hardware.* and android.software.*, copied during the build process from the
AOSP files, as well as possibly some vendor provided files.

229

---

**Page 96**

Android Internals::A Confectioner's Cookbook (Volume 1)

Dalvik Code Signing

Permissions by themselves are somewhat useless - after all, any app can declare whatever
permissions it requires in its AndroidManifest.xml, and the unwitting user will probably click "ok" when
prompted. To bolster security, Google requires digital signatures on applications uploaded to the
Play store, so as to identify the developer(s) behind them, and add accountability.

Thus, all Android applications must be signed (with the process explained in Volume II. What's
not so clear is - by whom. As Google was playing catch-up to Apple and opened the Play Store, it
wanted to offer an advantage to developers, in the form of a simpler process. As opposed to Apple's
lengthy validation process - all apps must be vetted by Apple, and digitally signed by them, Google
offered anyone the ability to just create a key pair, publish their public key, and use the private key
to sign their APK file. The rationale was that this achieves a similar level of identifying the APK's
source, while at the same time greatly simplifying the process of submitting applications to the
Store.

In practice, this led to an explosion of Malware in the Play Store. The Google approach was that
any malware found and reported would be removed from the Store, and the corresponding public
keys blacklisted. From the malware author's side, this was a case of "better to beg forgiveness than
ask permission" - as the malware by then would have likely propagated by the time it was detected,
thus achieving its purpose. This, coupled with the fact that a malware developer could always
generate a new key pair, hollowed out the entire security model. A recent study published in RSA
2014? found that "malicious apps have grown 388 percent from 2011 to 2013, while the number of
malicious apps removed annually by Google has dropped from 60% in 2011 to 23% in 2013", and
that effectively one out of every 8 apps in the store is, in fact, malicious.

The Android "Master Key" vulnerability

One of the most serious vulnerabilities discovered in Android (in 2013) is what came to be
known (somewhat erroneously) as the "Master Key Vulnerability". The vulnerability (discovered by
BlueBox security**, and refined (among others) by Saurik*®, the noted creator of iOS Cydia) occurred
in of mishandling of APK files which contained files with duplicate names. APKs are ZIP files, and
normally most utilities - aapt included - would not allow duplicate file names in the same zip.
Technically, however, it is possible, and introduced a peculiar vulnerability: File signature verification
was performed on the first entry in the APK, whereas extraction was performed on the second! This
oddity was due to two different libraries - Java's and Dalvik's native implementation - being used for
the tasks. As a consequence, it followed that anyone could take a validly signed APK file, and just
add additional files with the same names as the original (including classes.dex, of course). This
effectively bypassed Android's signature validation on APKs. Though fixed, the bug is a great
example of oftentimes gaping vulnerabilities which need little to no technical knowledge in order to
exploit.

The Android "Fake ID" vulnerability

The 2014 counterpart of the "Master Key" vulnerability became known as the "Fake ID"
vulnerability. This time, a fault in Android's certificate validation allows the forgery of an application's
identity, by supplying a deliberately broken certificate chain: Packing a malicious app (with a fake
certificate) along with a real (though unrelated) one, or even several. As a consequnce, a malicious
app could inherit the permission sets given to trusted apps (the example commonly given was
impersonating Adobe's components and becoming a Webkit plugin).

The vulnerability (also discovered by BlueBox®) generated a big buzz at the Black Hat
conference of that year, especially considering it was exploitable for almost four years - since
Eclair(!) - at the time affecting all devices on the market - up to and including KitKat. Google
eventually patched this, and it is no longer an issue with L - but (along with numerous other
examples) it just comes to show that security vulnerabilities do abound”.

* - As an anecdote, Apple's iOS 6.x-7.0.4 all suffered a similarly embarassing bug - the so called SSL "goto fail" - which was
the result of code accidentally(?) left behind that effectively bypassed SSL certificate validation. Apple was ridiculed by
Andro-philes.. demonstrating that people in glass houses shouldn't throw stones.

230

---

**Page 97**

Chapter VIII: Security

User Level Security

So far, the discussion in this chapter focused on application level security. Android also needs to
offer security at the user-level, allowing only the legitimate device user access to it, and in particular
its sensitive data. Beginning with JellyBean, Android supports multiple users, which complicates
matters a little.

The Lock Screen

The lock screen is a device's first and only real line of defense against theft or physical
interception by malicious entities. It is also the screen most often seen by the user, when the device
awakens from its frequent slumber. As such, it must be made resilient, on the one hand, but also
natural and quick, on the other. As with most Android features, vendors may customize this screen,
though Android provides an implementation which is often used as is.

Passwords, PINs and Patterns

The default Android lock screen allows either passwords, PINs or "patterns". Patterns are, in
effect, PINs, but instead of remembering actual digits, the user simply has to swipe a grid (usually
3x3). The user can opt for an actual PIN instead, which is technically stronger than a pattern in that
its length may be up to 16 characters, and it may repeat digits. A password provides a further
enhancement over a PIN in that it allows a mix of different case letters and numbers.

The lock screen is, in effect, just an activity, implemented by the com. android. keyguard
package. The package contains all the primitives for the system supplied lock screens and methods,
and includes the following classes:

Table 8-8: The classes in com. android. keyguard

Class provides

BiometricSensorUnlock Interface used for biometric methods, e.g. FaceUnlock

Keyguard[PIN|SimPin|Password] View] Default views to prompt for PIN or password credentials

KeyguardSecurityView Implemented by keyguard views (emulates activity lifecycle)
KeyguardService Keyguard Service implementation
KeyguardSecurityCallback Interface implemented by KeyguardHostView
KeyguardViewMediator Mediates events to the Keyguard view

The lock screen invocation begins when the power manager wakes up the display, and notifies
the implementation of the WindowPolicyManager. This calls the KeyguardServiceDelegate's
onScreenTurnedon, which waits for the keyGuard. From there, it falls on the keyGuard to draw
the lock screen (via some activity), and handle whatever lock credentials mechanism was chosen by
the user. The lock screen can also be invoked from the DevicePolicyManager's lockNow
method, when the system policy enforces automatic locking.

The actual logic of handling the lock is performed by LockPatternUtils, which calls on the
LockSettingsService, a thread of system_server. The service, in turn, verifies the input
against LOCK_PATTERN_ FILE (gesture.key) Of LOCK_PASSWORD_FILE (password.key, for PINs and
passwords alike). In both cases, neither pattern nor passwords are actually saved in the file, but
their hashes are. The service additionally uses the locksettings.db file, which is a SQLite database
which holds the various settings for the lock screen. Those are shown in table 8-9:

231

---

**Page 98**

Android Internals::A Confectioner's Cookbook (Volume 1)

Table 8-9: The locksettings.db database keys

LockPatternUtils constant

Key name (lockscreen.*)

LOCKOUT_PERMANENT_KEY

lockedoutpermanently

LOCKOUT_ATTEMPT_DEADLINE

lockedoutattempteddeadline

PATTERN _

EVER_CHOSEN_KEY

patterneverchosen

PASSWORD_TYPE_KEY

password_type

PASSWORD_TYPE_ALTERNATE_KEY

password_type_alternate

LOCK_PASSWORD_SALT_KEY

password_salt

DISABLE _ LOCKSCREEN_KEY

disabled

LOCKSCREEN BIOMETRIC WEAK FALLBACK

biometric_weak_fallback

BIOMETRIC_WEAK_EVER_CHOSEN_KEY

biometricweakeverchosen

LOCKSCREEN_POWER_BUTTON_INSTANTLY_LOCKS

power_button_instantly_locks

LOCKSCREEN_WIDGETS_ENABLED

widgets_enabled

PASSWORD_HISTORY_KEY

passwordhistory

Putting these components together, Figure 8-3 demonstrates a slightly simplified flow through

which the device is unlocked:

Figure 8-3: Unlocking the device

=

|, verifyPasswordAndUniock()

checkPassword()

checkPassword()

passwordToHash()

/data/system/password.key

onPatternDetected()

checkPattern()

checkPattern()

patternToHash()

/data/system/gesture.key

/data/system/locksettings.db a

( L Addition)

The TrustManager is an L addition, which helps unlock the device without a pattern - but by
alternate lock methods, such as a paired BlueTooth dongle or device.

232

---

**Page 99**

Chapter VIII: Security

CREATE
INSERT
CREATE

INSERT
INSERT
INSERT
INSERT
INSERT
INSERT
INSERT

. dump

Experiment: Viewing the locksettings.db

If your device is rooted and you have the SQLite3 binary installed, you can inspect the
locksettings.db file. You can also use adb to pull the locksettings.db to your host.

Output 8-13 Viewing the lock settings Database

root@htc_m8wl:/data # sqlite3 /data/system/locksettings.db
SQLite version 3.7.11 2012-03-20 11:35:50

Enter ".help" for instructions

Enter SQL statements terminated with a ";"

sqlite>
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

TABLE android_metadata

(locale TEXT) ;

INTO "android_metadata" VALUES('en_US')j;

TABLE locksettings

INTO
INTO
INTO
INTO
INTO
INTO
INTO

locksettings
locksettings
locksettings
locksettings
locksettings
locksettings
locksettings

(_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,user INTEGER,value TEXT) ;
VALUES (2, 'lockscreen.options',0,'enable_facelock') ;
VALUES (3, 'migrated',0,'true');
VALUES 'lock_screen_owner_info_enabled',0,'0');
VALUES 'migrated_user_specific',0,'true')j;
VALUES (9, 'lockscreen.patterneverchosen',0,'1');
VALUES (11, 'lock_pattern_visible_pattern',0,'1');
VALUES (12, 'lockscreen.password_salt',0,'-3846188034160474427') ;

(2
)
(4
(5

,
,

INSERT
INSERT
INSERT
INSERT
INSERT
INSERT
INSERT
DELETE
INSERT
COMMIT;

INTO
INTO
INTO
INTO
INTO
INTO
INTO
FROM
INTO

VALUES (81, 'lockscreen.disabled',0,'1'); # No Lock
VALUES (82, 'lock_fingerprint_autolock',0,'0');
VALUES (83, 'lockscreen.alternate_method',0,'0');

4

locksettings (
(
(
VALUES ( ,'lock_pattern_autolock',0,'0');
(
(
(

locksettings
locksettings 8

locksettings 8

locksettings VALUES (86, 'lockscreen.password_type_alternate',0,'0');
locksettings VALUES (87, 'lockscreen.password_type',0,'131072')j;
locksettings VALUES (88, !lockscreen.passwordhistory',0,'');
sqlite_sequence;

"sqlite_sequence" VALUES ('locksettings', 88) ;

# PIN

The columns in the locksettings table includes "user" (to support Android Multi-User login, as
of JB). The values are usually boolean (0/1), but not always - there are some flag combinations,
and a salt for the .key file. You can use SQL statements to change the lock settings from within
SQLite3. though they will be cached by the lock settings service. You can also just rename the file
- if you do so and restart system_server, it will be recreated with the defaults (and also have
the nice side effect of resetting your password or pattern).

Alternate lock methods

Ice Cream Sandwich introduced face recognition as an alternative to the traditional methods.
This was touted to much fanfare, as a potential differentiator against iOS. Unfortunately, the
recognition rates are far from perfect - figures range from as low as 60% to 90%. Face recognition
can also easily be defeated - by holding up a picture to the phone. Interestingly, people who have
tried this method found it works with greater accuracy than the user's actual face...

The Motorola Atrix 4G was the first Android device to implement fingerprint scanning as an
alternative method. This also suffered poor recognition rates. Apple's acquisition of Authentec in
2012 suggested fingerprint authentication was coming to iOS and, indeed, it made its debut in the
iPhone 5S. Samsung initially slammed this as a poor, uninnovative feature, but nonetheless (and
unsurprisingly) went on to introduce it to their "next big thing", the Galaxy S5. Other Android
vendors are quickly following, and it seems this will become a standard feature, with L offering built-
in support through its fingerprint service.

Another important addition in L is the notion of unlocking the device using another device - a
paired BlueTooth device such as Android Wear, which works by proximity alone - leaving the device
unlocked so long as the user is nearby. TrustManager, fingerprint, and the internals of
LockSettings are discussed in volume II.

233

---

**Page 100**

Android Internals::A Confectioner's Cookbook (Volume 1)

Multi-User Support

For the majority of its existence, Android has operated under the assumption that the device
only has one user. Unlike desktop systems, which have long allowed user login and switching, this
feature was only introduced into Android with JellyBean (4.2), and has been initially introduced only
into tablets.

Android already uses the user IDs for the individual applications, as explained previously. To
implement multi-user support, it builds on the same concept, by carving up the AID space into non-
overlapping regions, and allocating one of every human user. Application IDs are thus renamed from
app ### to u##_a###, and users are created with separate directories in /data/user. Application
data directories are moved to /data/user/##/, with the primary user being user "0". The legacy
/data/data thus becomes the primary user's directory (symlinked from /data/user/0). The user profiles
themselves are stored in /data/system/users. This is shown in the following experiment:

Experiment: Enabling multi-user support on API 17 and later

On tablets, multi-user support will be enabled by default as of JellyBean (API 17). A little
known feature, however, is that you can enable it on phones as well. All it takes is setting a
system property - fw.max_users to any value greater than 1. Doing so on the Android emulator
will bring up the "Users" option to settings, as shown in the following screenshot:

Screenshot 8-1: Before and After fw.max_users property modification

o Settings o& Settings

Display

a een = Storage

F4 Apps

PERSONAL

Battery

Apps
9 Location =

; Users
@ Security
PERSONAL

G3 Language & input

9 Location

© Backup & reset ;
@ Security

ACCOUNTS

S Cc 6! a)

Adding a user is straightforward, though the system will force you to set a lock screen, in
order to differentiate between the two users on login. The process should look something like

Output 8-14 (next page)

234

---

**Page 101**

Chapter VIII: Security

Experiment: Enabling multi-user support on API 17 and later (cont)

Output 8-14: Listing multiple user profiles in /data/system/users

eneric:/data/system/users # 1s -F

userlist.xml

root@generic:/data/system/users # setprop fw.max_users 3

#

# Add another user through settings.. (shell stop/start might be necessary) then ls again

eneric:/data/system/users # 1s -F

0.xml
10/
10.xml
userlist.xml
root@generic:/data/system/users # cat userlist.xml
<?xml version='1.0!' encoding='utf-8' standalone='yes' ?>
<users nextSerialNumber="11" version="4">5
<user id="0" />
<user id="10" />
</users>
root@generic:/data/system/users # cat 0.xml # Display details for user 0
<?xml version='1.0!' encoding='utf-8' standalone='yes' ?>
<user id="0" serialNumber="0" flags="19" created="0" lastLoggedIn="1400702272027"
icon="/data/system/users/0/photo.png">
<name>Owner.com</name>
<restrictions /> # restrictions, if any, go in this element
</user>
root@generic:/data/system/users # ls -1 0 # Show settings for user 0
-rw-rw---- system system ... accounts.db # External (POP3, IMAP, etc) accounts
system system ... accounts.db-journal # SQLite3 journal
system system ... appwidgets.xml # Installed widgets
system system ... package-restrictions.xml # Package Restrictions
system system ... photo.png # User selected photo
system system ... wallpaper # Selected wallpaper
system system ... wallpaper_info.xml # MetaData

From the command line, the same effect can be achieved by using pm create-user, which
connects to the user manager
(lUserManager.Stub.asInterface (ServiceManager.getService ("user") )) and
invokes its createUser() method. The pm remove-user likewise removes a user.

Depending on how you create the user (as a separate user or a restricted user, which shares
the original user's apps), the restrictions element may be populated with the following
boolean attributes, all defined in the android.os.UserManager Class. The actual handling of
the files (above) and the restrictions is performed by
com.android.server.pm.UserManagerService.

Table 8-10: User Restrictions
Restriction

no_modify accounts

no_config wifi

no_install_apps

no_uninstall_apps

no_share_location

no_install_unknown_sources

no_config_bluetooth

no_config_credentials

no_remote_user

235

---

**Page 102**

Android Internals::A Confectioner's Cookbook (Volume 1)

Android relies extensively on cryptographic keys, for system internal use (validating installed
packages) and for application use. In both cases, the keystore service (discussed in Chapter 4) plays
an integral part in abstracting and hiding the implementation.

Certificate Management

Public Key Infrastructure is the de-facto fulcrum of all Internet security. Encryption rests on
several key assumptions which relate to the algorithms and methods behind public keys, the most
important of which is a trust. Simply put, this means that if you know a subject's public key, the key
can be used not just for encrypting messages to it, but also authenticating messages from it. This,
in turn, means that if this subject vouches for another public key by authenticating it (which is, in
effect, what a certificate is), then that public key's ownership can be established. In this way, a trust
hierarchy can be formed.

This principle, while powerful, does lead to a chicken and egg problem - you can authenticate a
public key only if some other public key has been a priori used to authenticate it. The way around
this predicament is to hard code the initial public keys in the operating system. These keys are
encoded in the form of root certificates - public keys authenticating themselves. When passed over
the network, they are of no value (as they are trivial to spoof). When hard-coded, however, they
can be trusted and provide the basis for the trust hierarchy.

Android hard-codes root certificates in /system/etc/security/cacerts. The certificates are encoded
in their PEM (Privacy-Enhanced-Mail) form, which is a Base64 encoding of the certificate between
delimiters. Some devices will also have the plain ASCII form of the certificate before or after the
PEM encoding. If not, it's a simple matter to display it using the openss1 command line utility,
which is built-in to Linux or Mac OS, shown in output 8-15:

Output 8-15: Using openss1 to decode a PEM certificate

morpheus@Forge (/tmp)$ adb pull /system/etc/security/cacerts
pull: building file list...
pull: /system/etc/security/cacerts/f££783690.0 -> ./cacerts/ff£783690.0

morpheus@Forge (/tmp)$ openssl x509 -in ££783690.0 -text | more
Certificate:
Data:
Version: 3 (0x2) # Denotes the X.509v3 format
Serial Number: # Used to refer to certificate when revoking
44:be:0c:8b:50:00:24:b4:11:d0d3:36:2a:fe:65:0a:fd
Signature Algorithm: shalWithRSAEncryption
Issuer: # Issuer in LDAP notation: C=country, ST=state, L=location,
# O=Organization, OU= Organizational Unit, CN=Common Name

Validity
Not Before: # Usually coincides with certificate issue date
Not After : # Usually set to 2-10 of years from issue date
Subject: # Certificate Owner, in same LDAP notation
# ...
Subject Public Key Info:

. # Modulus and Exponent (usually 65537)
X509v3 extensions:
X509vV3 Key Usage:
Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
X509v3 Basic Constraints: critical
CA:TRUE
X509v3 Subject Key Identifier:
A1:72:5F:26:1B:28:98:43:95:5D:07:37:D5:85:96:9D:4B:D2:C3:45
X509v3 CRL Distribution Points:
URI:http://crl.usertrust.com/UTN-USERFirst-Hardware.crl
X509v3 Extended Key Usage:
TLS Web Server Authentication, IPSec End System, IPSec Tunnel, IPSec User
Signature Algorithm: shalWithRSAEncryption
# .. SHA-1 hash of certificate, signed with RSA private of issuer
BEGIN CERTIFICATE
MIIEGDCCA1ygAwI BAgIQRL4Mi1lAAJLQROzYq/mUK/TANBgkqhkiG9w0BAQUFADCB
1zELMAkGA1UEBhMCVVMxCzAJBgGNVBAgTA] VUMRcwFQYDVOQHEWS5TYWx0 IExha2Ug
Base 64 (original PEM) encoding of the certificate
KqMiDP+JJn1fIytH1xUdqwqeUQ0qUZ6B+dQ7XnAS fxAynBé 7nfhmqA==
END CERTIFICATE

236

---

**Page 103**

Chapter VIII: Security

Of special importance are the Over-The-Air (OTA) update certificates, stored in the
/system/etc/security/otacerts.zip archive. The archive usually contains one (rarely, more) certificates
which are used for validating OTA updates (described in Chapter 3). The RecoverySystem Class
parses this file (hardcoded as DEFAULT_KEYSTORE), in its getTrustedCerts() method using a
CertificateFactory. Once again, any certificates would be encoded in PEM (usually, without
human readable text), but you can use the method shown in output 8-13 to decode them.
Removing this file is a good method to "combat" auto-updates in some Android distributions (such
as FireOS), which may cause you to lose root access post-update.

Certificate Pinning

JellyBean (API 17) introduces certificate pinning, which has become a common add-on to SSL
certificate validation. Pinning involves hard-coding the expected public key of a host (via its
certificate), so that if the host presents a certificate which does not match the pin (or one of the
pins in a pin set) it is rejected.

Unlike the certificates discussed previously, which are in /system/etc/security (and therefore
cannot be modified), pins are maintained in /data/misc/keychain/pins, which is a file that can be
replaced. The Cert PinInstallReceiver Class registers a broadcast receiver for the
UPDATE _PINS intent, and - when such an intent is received, its extras are expected to contain the
following:

e EXTRA CONTENT PATH: The file name containing the new pins.
e EXTRA VERSION NUMBER: Which is expected to be greater than the current version.

e EXTRA REQUIRED HASH: Of the current pins file.

e EXTRA SIGNATURE: Signature of the file supplied, its version and hash of current pins file

The Cert PinInstallReceiver's onReceive (inherited from
ConfigUpdateInstallerReceiver) gets the values from the broadcast intent, ensures the
version number is indeed greater than the current version of the pins file (in
/data/misc/keychain/metadata/version), and that the current file's hash matches the hash specified in
the intent. It then verifies the signature, using the certificate stored in the system settings database
under config update certificate (the UPDATE CERTIFICATE KEY). If everything is in
order, the filename from the intent is copied over the existing pins file, and the metadata/version is
updated to reflect the new version number.

Google pins all of its (many) certificates by default, and the vendor may pin additional ones. A
quick way of looking at pins is shown in Output 8-16:

Output 8-16: Displaying the pinned domains

root@htc

* spreads

* chart

appengine
.google-
.doublec
. chrome .goog

‘ plus.google.c

youtube.com
google.com
-mail.goog
www.googlemail.com
gmail.com

The Android Explorations Blog’ contains a sample application demonstrating the creation of a
pins file and its update operation through the intent.

237

---

**Page 104**

Android Internals::A Confectioner's Cookbook (Volume 1)

Certificate Blacklisting

Android provides the CertBlacklister class to handle black listing (effectively, revocation)
of certificates. The class (instantiated as a service of system_server, as discussed in Chapter 5)
registers an observer for two content URIs:

e content://settings/secure/pubkey_blacklist: Stores known compromised or revoked public keys
or certificates. Content written here ends up written to
/data/misc/keychain/pubkey_blacklist.txt.

© content://settings/secure/serial_blacklist: Stores known compromised or revoked serial
numbers of certificates. Serial numbers written here are saved to
/data/misc/keychain/serial_blacklist.txt.

Both values are also in the system's secure settings, as can be seen in the following output:

Output 8-17: Viewing the serial and pubkey blacklists

root@htc_m8wl:/ # sql ites /data/data/com.android.providers.settings/databases/settings. \

t_* from secure" | grep black

95|serial_ blac
99 [pubkey_ bl 5 5 83333c9687d£63377efceddd82efa..

reddd82efa9101913e

Secret and Private Key Management

Storing secrets - symmetric keys or the private part of a public-key pair - poses serious
challenges for any security infrastructure. If one assumes that file permissions are a strong enough
layer of security, the secrets can be placed in a file and appropriately locked down. The underlying
file permissions of Linux, however, are inflexible, and configuration errors could lead to secret
leakage. Likewise, there is the problem of obtaining root access - which effectively voids all
permissions, leaving everything in the clear.

Android provides access to secrets via the keystore service. This service has already been
discussed in Chapter 4. Keystores for applications are maintained on a per-user basis, in the
/data/misc/keystore/user_## directory, but applications have no direct access to that directory, and
must go through the keystore service, which is the sole owner of the directory (permissions 0700).
The service also provides public key functions - generate, sign and verify - without allowing
applications any access to the underlying private keys. This allows the key storage to be potentially
implemented in hardware.

Indeed, Android offers hardware backed secure storage, on those devices which support it, as
of JellyBean. As discussed in Chapter 11, the keymaster HAL abstraction provides both a uniform
interface for encryption operations, and allows its implementation in both software and hardware.
Thus, supporting devices implement a hardware backed keymaster module, whereas those which do
not use a softkeymaster instead.

238

---

**Page 105**

Chapter VIII: Security

Storage Security

/data Encryption

While most users remain oblivious to the need for encryption on their devices, corporate users
certainly fear the compromising of data which would ensue should a device be lost or stolen. iOS
provided transparent encryption as of iOS 4, and coincidentally, so has Android as of Honeycomb. By
using the very same dm-crypt mechanism utilized by OBBs and ASEC, Honeycomb extends the notion
of encryption to the full filesystem layer. The term "full disk encryption" is therefore somewhat
inaccurate here, since it is only the /data partition which is normally encrypted. This actually makes
more sense, because /system contains no sensitive data (and would be impacted from the latency
incurred by crypto-operations.

Android's documentation provides a detailed explanation of encryption, which has been revised
for Android L® . As with ASECs and OBBs, the volume manager is responsible for performing both
the filesystem encryption and decryption. The former is performed when selected by the user, and is
a rather lengthy operation. The latter is performed transparently, when the encrypted filesystem is
mounted as a block device using the device mapper.

Note, that unlike obb and asec - the decryption keys for which are stashed somewhere on the
device in plaintext, albeit readable only by root - the key for the /data partition encryption does not
actually reside on the device, but requires the user to interact during boot, and supply it (or, more
accurately, the password from which this key is derived). This requires modifications to the Android
boot process, as well as an interaction between init and vold, which we describe in Chapter 4

Prior to the dm-crypt solution, there were several proposed alternatives for file system
encryption (most notably EncFS by Wang et Al.°), but the dm-crypt one is the de facto standard,
now that L has enabled it by default. The architecture is shown in Figure 8-4:

Figure 8-4: The DM-Crypt Architecture

1) Client process initiates a filesystem request

USER MODE

KERNEL MODE

2) VFS layer determines target FS (ext4 or other)

3) Filesystem driver (mounted over
dm-crypt volume) translates to block requests

Kernel caches store
Both encrypted and

Decrypted data, thus
reducing overhead as

4) dm-crypt redirects
much as possible

To real (encrypted) volume

5) Encrypted data returns to dm-crypt,
which performs decryption using
built-in kernel crypto functions, or
hardware acceleration, if present

Android M (PR1) further employs dm-crypt with a new feature called "adoptable storage", which
enables the user to extend Android filesystem encryption to external storage (e.g. USB drivers). As usual,
this is handled by vold, who maintains the encryption keys in /mnt/vold, and mounts the decrypted
volumes under /mnt/expand.

239

---

**Page 106**

Android Internals::A Confectioner's Cookbook (Volume 1)

Performance Impact

An oft asked question pertains to the potential performance impact of encryption. Encryption naturally
requires more processing by the CPU (to decrypt and re-encrypt the data), which can impact performance
and, to an extent, power consumption. While there have been differing accounts, the overall view is that
the performance impact ranges from negligible to manageable. This is corroborated by the following:

e Access to the storage device is already inherently slow: While not as slow as hard
drives, flash devices run at significantly slower rates than the CPU. Adding the overhead of

an encryption or decryption routine adds several more microseconds per access, but when
viewed percentage-wise, this accounts for a fractional gain, at best.

e The Linux kernel optimizes access with caching: As can be seen in figure 8-4, the
Linux kernel helps optimize data access by caching device data. Because dm-crypt appears as

a block device, it exists under the caches, and therefore can benefit from it: Data is
decrypted only once, and read/write operations can occur on the cached (decrypted) copy.
When the data is flushed back to the underlying device, it can be re-encrypted, and then find
its way to the underlying physical device.

e To begin with, access to /data isn't as often as to /system: Unlike access to the
/system partition, which stores Android's vast frameworks and static configuration, access to

/data occurs only when an app is loaded, or some runtime configuration change occurs.

Secure Boot

KitKat introduced a new feature for securing the boot process, using the kernel's device
mapper. This feature, known as dm-verity originated in Chromium OS, and has been ported into
Linux (and thus Android), beginning with kernel version 3.4.

Recall from Chapter 3, that a chain of trust (also known as the verified boot path) has been
established from the ROM, via the boot loader, and onto the kernel and the root file system (i.e. the
boot partition). While the bootloader actually does verify /system, it does so only when flashing the
entire partition - which leaves open the avenue for a root owned process (be it "rooting" or
malware) to make persistent changes in /system, by remounting it as read-write, and modifying files
in it. Using dm-verity effectively extends the boot chain of trust one more level, onto /system.

Verifying the integrity of a partition is the simple matter of hashing all of its blocks (DM-Verity
uses SHA-256), and comparing that hash against a stored, digitally signed hash value. To do so
effectively, however, one has to avoid the lengthy process of reading the entire partition, which can
delay boot. To get around this limitation, dm-verity reads the entire partition only once,and records
the hash value of each 4k block in the leaf nodes of the tree. Multiple leaf nodes are rehashed in the
second level of the tree, and then onward to the third, until a single hash value is calculated for the
entire partition - this is known as the root hash. This hash is digitally signed with the vendor's
private key, and can be verified with its public key. Since disk operations are performed in full
blocks, it is a straightforward to add an additional hash verification on the block as it is placed into
the kernel's buffer/page cache, and before it is returned to the requester. If the hash check fails, an
I/O error occurs, and the block is known to be corrupted.

The dm-verity feature is touted for malware prevention, since it effectively prevents any
modification of /system, but does have the side effect of preventing unauthorized persistent rooting,
as well. Malware could definitely attempt to make modifications to /system, but Android would
detect them, potentially refusing to boot - yet the same would apply for any "persistent root" back
door, e.g. dropping a SetUID /system/xbin/su. From the vendor's perspective, this is fine - most
vendors would only provide root via bootloader unlocking, which breaks the chain of trust at its very
first link. Further, dm-verity requires only a subtle modification to the update process (discussed in
Chapter 3) - namely, that the vendor regenerate the signature when /system is modified during an
update. Otherwise, /system remains read only throughout the device's lifetime, and the signature
must therefore remain intact.

The kernel mode implementation of dm-verity is rather small - a 20k file of drivers/dm/dm-
verity.c, which plugs into the Linux Device Mapper (as discussed in Volume III). Google details the
verified boot process in the Android Documentation?®. The Android Explorations Blog! once more
provides further detail, including using the veritysetup during the building of the image.

240

---

**Page 107**

Chapter VIII: Security

Rooting Android

Most vendors provide ADB functionality on their devices and leave the operating system
relatively open for developers, but few (if any) provide root access to the device. There is a strong
rationale not to do so, considering that obtaining root access to a UNIX system brings with it virtual
omnipotence - and Android is no different. Leaving behind open access to root would also potentially
provide an attack vector for malware (which Android knows no shortage of). With root access, any
file on the system could be read, or - worse - overwritten, which would give an attacker both access
to private data, as well as the ability to hijack control of the device.

The same can be said for Apple's iOS (also a UNIX system, based on Darwin), but herein lies
the significant difference between the two. Apple's developers have engineered the system from the
ground up, literally, from the very hardware to the uppermost layers of software, to be rock solid
and not to allow root access (in fact, not to allow any access aside from a sandboxed app model) at
all costs. Android is built on Linux, which itself is a mix of code strains from different contributors,
not all of which adhere to the strictest security standards. Additionally, several vendors leave an
avenue, which can be exploited (by a human user in possession of the device) to gain root access -
redirecting the system to boot an alternate configuration. Another way of looking at it is, Android
considers the application to be the enemy - whereas iOS considers the user itself to be one.

Boot-To-Root

When Android devices boot, they normally do so by the process described in Chapter 3. It is
possible, however, to divert the boot process to an alternate boot, for "safe" boot, system upgrade,
or recovery. This can usually be done by pressing a physical button combination (usually one or
both of the volume buttons, and the home button, if it exists), or by a fastboot command, when the
device is connected over USB. Once the boot flow is diverted, the boot loader can be directed to
load an alternate boot image - either the on-flash recovery image, an update supplied on the SD-
card, or (over USB) an image supplied through fastboot.

If a device's bootloader can be unlocked (as explained in Chapter 3) the device can be rooted.
It's that simple. As previously mentioned, unlocking the boot loader will cause /data to be effaced, in
an effort to prevent the user's sensitive data from falling into the wrong hands. Additionally, some
boot loaders will permanently set a flag indicating that the loader has been tampered with, even if it
is re-locked at some point. This is to note that the boot loader basically shirks all responsibility for
system security, as it will no longer enforce digital signatures on images flashed.

All it takes to "root" the device is really just one part of the device image - the init RAM disk
(initramfs). Because the kernel mounts the initrd as the root filesystem and starts its /init with root
privileges, supplying an alternate /init - or even just a different /init.rc file - suffices to obtain root
access. From that point onwards, it's a simple matter of convenience: It's straightforward to simply

have ADB maintain root privileges (by setting ro. secure=0*) or replace adb to a version which

doesn't drop privileges. Most rooting tools, however, usually drop a su binary into /system/bin or
/system/xbin, and use chmod 4755 to toggle the setuid bit, so when it is invoked from the shell, the
setuid effect will kick in, and automatically bestow root permissions. The code for such a binary (pre
Kit-Kat) is so simple it can be summarized in three functional lines:

Listing 8-5: A simple implementation of su, for non SE-Linux enforced devices

#include <stdio.h>
void main(int argc, char **argv)
{
setuid(0);
setgid(0);
system("/system/bin/sh") ;

* - In recent builds, adb is conditionally compiled (#ifdef ALLOW_ADB_ROOT) so as to ignore this property.

241

---

**Page 108**

Android Internals::A Confectioner's Cookbook (Volume 1)

You can find a similar implementation (with command line options) in the AOSP's
/system/extras/su/su.c. AS of KitKat, however, the introduction of SE-Linux in enforcing mode makes
the binary less trivial, in that its parent (the shell) is already confined to a restricted execution context
(u:r:shell1:s0), which it cannot break out of. This requires the su binary to make an IPC call to a
process in the u:r:init:s0 (or u:r:kernel:s0) unrestricted context, to then spawn a shell (e.g.
the WeakSauce exploit (with DaemonSu), as explained on the book's companion website’’).

If you've rooted a KitKat (or later) device with SE-Linux in enforcing mode, you can likely see
this for yourself, as shown in the following output:

Output 8-18: viewing an su implementation, accommodating for SELinux

shell@htc_m8wl:/ $

graphics) ,1004 (input) ,100
01 (net_bt_admin) ,3 (net_

shell@htc_m8wl:/ $
tc_m8wl:/ #

O(root) context=u:r:init:s0

/system/bin/sh

su

daemonsu: 0
6506 tmp-m

intrusted_app:sC u0_al40 575 eu.chainfire.supersu
:r:init:s0 root 6510 ps

The practice of rooting is so popular that there are quite a few "SuperUser" applications, which
provide a GUI interface to administer root access, once the device is rooted. The applications
actually offer a programmatic API (via permissions and intents) to allow other applications access to
root. One noteable example is chainfire's SuperSU, which defines its own Dalvik level permissions
(android.permission.ACCESS SUPERUSER and
eu.chainfire.supersu.permission.NATIVE) and enables applications to broadcast intents in
order to obtain superuser privileges. This application also cleverly works around SE-Linux, as can be
seen from the output above.

Rooting via Exploiting

Whether or not a vendor has left the boot-root backdoor open, often there exist additional
backdoors. These, unlike the former, are quite unintentional, and all rely on some form of system
vulnerability exploitation. The ways to do so are myriad, and often unpredictable until discovered,
but they all share the same common denominator: Find some insecure configuration setting or
software component, and trigger some code path, by means of which root access can be obtained.
As mentioned in the threat modeling section of this chapter, the security jargon for these attack
types is privilege escalation, as it refers to the process wherein a lower privilege process (that is,
some app), can increase its privileges, usually first to those of the system user, and then root.

242

---

**Page 109**

Chapter VIII: Security

There is a strong similarity between exploit-based rooting methods and "jailbreaking" for iOS. In
both cases, it takes the discovery and exploitation of software bugs, and both methods should not
be possible in a perfect world (at least, according to Google and Apple). Once these methods are
discovered, their days are numbered: The operating system is fairly quickly patched, and suggested
to the user for download and updated (or even auto-updated, as for example with the Amazon
Kindle). One prominent example was in Gingerbread, wherein Google itself pushed an update for a
vulnerability in the Linux kernel, known at the time to have been actively exploited by malware.

A thorough discussion of exploitation techniques is thus beyond the scope of this work, and
quite frankly is pointless, since all known exploits at this time have been patched. Exploits generally
obtain root by passing crafted input to a process already running as root (vold has been a perennial
favorite..), corrupting its memory (stack or heap) and usually overwriting a function pointer (or,
commonly, a return address) to subvert its execution, and direct it at the attacker-controlled input.
An additional trick - Return Oriented Programming (ROP) is often used to direct execution to
snippets of code which already exist in the program, but run in an attacker controlled manner. This
method, which is somewhat like biological DNA splicing and recombination, defeats data execution
prevention methods, such as ARM's XN bits. A lengthy discussion of past exploits and ROP methods
can be found in the Android Hacker's Handbook.

It should be noted that not all exploits necessarily involve code injection - some are much more
simple and elegant (for example, the "WeakSauce" exploit for HTC One phones, discssued in the
book's companion website’). Similarly, the latest vulnerability in Android at the time of writing was
not really due to Android - but to the Linux kernel. Geohot's clever "Towelroot" exploit'* used a well
known kernel bug in handling fast mutexes (CVE-2014-3153) to gain root. While TowelRoot itself is
not malware per se but a rooting utility, malware could use the exact same bug to surreptitiously
gain root access, without the user's knowledge or consent.

To paraphrase a quote attributed to Donald Rumsfeld - there are "known unknowns" - those
are essentially the 0-days which were unknown, but have been discovered - and patched - but there
are also "unknown unknowns". The latter are the 0-days which are likely to exist, but have not been
discovered yet, or - worse - have been discovered, but not publicized yet. Any hacker uncovering a
0-day in effect obtains a skeleton key to all Android devices vulnerable to that particular issue. A
malicious hacker can incorporate this into powerful malware, or not even bother, and directly sell it
on the open market. Though not as lucrative as iOS exploits, Android 0-days can fetch anywhere
between $50,000 and $500,000 dollars - depending on vector (local/remote) and impact.

Security Aspects of Rooting

Because a boot-based rooting method requires user intervention, and/or connecting the device
to a host, it is generally not considered to be an insecurity of the Android system. It does, however,
leave a clear attack vector for an adversary who gains possession of the device. This could be an
issue if the device is lost, stolen, or just left outside one's reach for a sufficient amount of time. It
would take a skilled attacker no more than 10-20 minutes to root a device, steal all the personal
data from it, and leave a backdoor or two. This is why most bootloaders are often locked, and while
an unlock of the bootloader is possible, it will force a factory reset and erasure of all personal data -
Once the bootloader is unlocked, however, the device is vulnerable (unless the bootloader is locked
again).

Exploitation attacks are even simpler in the sense that they do not require the user to manually
divert the system boot process. In fact, these attacks require no user intervention at all. Therein lies
their advantage (for those looking for a simple "1-click" root method), but also their great risk, as
they can be carried out without the user's knowledge, often when installing a seemingly innocuous
app, which like the proverbial Trojan horse compromises the entire system.

243

---

**Page 110**

Android Internals::A Confectioner's Cookbook (Volume 1)

Explotation attacks are even more dangerous when they are HTTP-borne. When the
vulnerability exploited, or part thereof, involves the browser, it suffices to visit a malicious website -
or inadvertently access some content from it (for example, through an ad network), for malicious
payload to target the browser, and gain the initial foothold on the device. Indeed, sophisticated
malware consists of multiple payloads injected over several stages, initially obtaining remote
execution, then followed by obtaining remote root.

What follows is that rooting the device can, in fact, be dangerous, if not carried out through
trusted sources: When an eager user downloads a rooting utility, whether one-click or tethered, if
the download source is not a trusted one, it could be hard - virtually impossible - to detect additional
payloads or backdoors which may be injected by such utilities. Less than proper tools may jump on
the chance to also change system binaries or frameworks, for example disabling the Dalvik
permission mechanism for malware purposes. Malware could possibly inject a rootkit all the way
down to the Linux kernel, though most would probably not put that much effort when it's fairly
trivial to hack the higher layers. Somewhat ironically, some of the SuperUser applications themselves
had vulnerabilities in the past, which enabled rogue applications to detect a rooted device, and
escalate their own privileges through the applications (q.v. CVE-2013-6774).

The last, but hardly least impact of rooting a device one has to consider is that on applications -
Android's Application content protections disintegrate on a rooted device: OBBs can be read by root,
as can the keys to ASEC storage. Application encryption likewise fails, and though hardware backed
credential storage offers some resistance, its client processes' memory can easily be read (via
ptrace (2) methods and the like). DRM solutions also fail miserably. Unfortunately, there's no
foolproof way of detecting a rooted device from a running application, and refusing to execute on
one.

Arguably, the same can be said for Jailbroken iOS - after all, Apple's fairplay protections and
application encryptions, though stronger than Android's, are equally frangible. Yet one has to keep
in mind that iOS only has an exploitation vector (with an ever increasing level of difficulty in
between releases), whereas most Android devices do allow Boot-to-Root. Coupled with the ease of
Dalvik bytecode decompilation, this poses a serious concern for application developers.

Summary

This chapter attempted to provides an overview of Android's myriad security features, both
those inherited from Linux, and those which are specific to Android and mostly implemented in the
Dalvik level. Special attention has been given to the Android port of SELinux - which, though
currently not in full effect, is already adopted by Samsung in KNOX, and is likely to play a larger part
in upcoming releases of Android.

While trying to be as detailed as possible, this review is by no means comprehensive. The
interested reader is referred to Android Security specific books, such as Nikolay Elenkov's Android
Security Internals’, which devotes full chapters to what was covered here in sections.

244
