%define cmsfsver 1.1.8c
%define vipaver 2.0.4

Name:           s390utils
Summary:        Utilities and daemons for IBM System/z
Group:          System Environment/Base
Version:        1.23.0
Release:        12%{?dist}
Epoch:          2
License:        GPLv2 and GPLv2+ and CPL
ExclusiveArch:  s390 s390x
URL:            http://www.ibm.com/developerworks/linux/linux390/s390-tools.html
# http://www.ibm.com/developerworks/linux/linux390/s390-tools-%%{version}.html
Source0:        http://download.boulder.ibm.com/ibmdl/pub/software/dw/linux390/ht_src/s390-tools-%{version}.tar.bz2
Source2:        s390.sh
Source3:        s390.csh
Source4:        http://www.linuxvm.org/Patches/S390/cmsfs-%{cmsfsver}.tar.gz
Source5:        zfcpconf.sh
# http://www.ibm.com/developerworks/linux/linux390/src_vipa-%%{vipaver}.html
Source6:        http://download.boulder.ibm.com/ibmdl/pub/software/dw/linux390/ht_src/src_vipa-%{vipaver}.tar.gz
Source7:        zfcp.udev
# files for the Control Program Identification (Linux Call Home) feature (#463282)
Source10:       cpi.initd
Source11:       cpi.sysconfig
# files for DASD initialization
Source12:       dasd.udev
Source13:       dasdconf.sh
Source14:       device_cio_free
Source15:       device_cio_free.service
Source16:       ccw_init
Source17:       ccw.udev
Source18:       cpuplugd.initd
Source19:       mon_statd.initd
Source21:       normalize_dasd_arg

Patch1:         s390-tools-1.23.0-fedora.patch
Patch2:         s390-tools-1.23.0-hardening.patch

Patch1000:      cmsfs-1.1.8-warnings.patch
Patch1001:      cmsfs-1.1.8-kernel26.patch
Patch1002:      cmsfs-1.1.8-use-detected-filesystem-block-size-on-FBA-devices.patch

Patch2000:      src_vipa-2.0.4-locations.patch

Requires:       s390utils-base = %{epoch}:%{version}-%{release}
Requires:       s390utils-osasnmpd = %{epoch}:%{version}-%{release}
Requires:       s390utils-cpuplugd = %{epoch}:%{version}-%{release}
Requires:       s390utils-mon_statd = %{epoch}:%{version}-%{release}
Requires:       s390utils-iucvterm = %{epoch}:%{version}-%{release}
Requires:       s390utils-ziomon = %{epoch}:%{version}-%{release}
Requires:       s390utils-cmsfs = %{epoch}:%{version}-%{release}


%description
This is a meta package for installing the default s390-tools sub packages.
If you do not need all default sub packages, it is recommended to install the
required sub packages separately.

The s390utils packages contain a set of user space utilities that should to
be used together with the zSeries (s390) Linux kernel and device drivers.

%prep
%setup -q -n s390-tools-%{version} -a 4 -a 6

# Fedora/RHEL changes
%patch1 -p1 -b .fedora
%patch2 -p1 -b .hardening

#
# cmsfs
#
pushd cmsfs-%{cmsfsver}
# Patch to fix a couple of code bugs
%patch1000 -p1 -b .warnings

# build on kernel-2.6, too
%patch1001 -p1 -b .cmsfs26

# use detected filesystem block size (#651012)
%patch1002 -p1 -b .use-detected-block-size
popd

#
# src_vipa
#
pushd src_vipa-%{vipaver}
# fix location of the library
%patch2000 -p1 -b .locations
popd


# remove --strip from install
find . -name Makefile | xargs sed -i 's/$(INSTALL) -s/$(INSTALL)/g'

pushd cmsfs-%{cmsfsver}
# cmdfs: fix encoding
iconv -f ISO8859-1 -t UTF-8 -o README.new README
touch -r README README.new
mv README.new README
# prepare docs
mv README README.cmsfs
mv CREDITS CREDITS.cmsfs
popd


%build
make OPT_FLAGS="$RPM_OPT_FLAGS -fno-strict-aliasing" DISTRELEASE=%{release} V=1

pushd cmsfs-%{cmsfsver}
./configure
make CC="gcc $RPM_OPT_FLAGS -fno-strict-aliasing"
popd

pushd src_vipa-%{vipaver}
make CC_FLAGS="$RPM_OPT_FLAGS -fPIC" LIBDIR=%{_libdir}
popd


%install
mkdir -p $RPM_BUILD_ROOT{%{_lib},%{_libdir},/sbin,/bin,/boot,/lib/udev/rules.d,%{_mandir}/man1,%{_mandir}/man8,%{_sbindir},%{_bindir},%{_sysconfdir}/{profile.d,sysconfig},%{_initddir}}

# workaround an issue in the zipl-device-mapper patch
rm -f zipl/src/zipl_helper.device-mapper.*

make install \
        INSTROOT=$RPM_BUILD_ROOT \
        MANDIR=$RPM_BUILD_ROOT%{_mandir} \
        LIBDIR=${RPM_BUILD_ROOT}/%{_lib} \
        DISTRELEASE=%{release} \
        V=1

install -p -m 644 zipl/boot/tape0.bin $RPM_BUILD_ROOT/boot/tape0
install -p -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/profile.d
install -p -m 644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/profile.d
install -p -m 755 %{SOURCE5} $RPM_BUILD_ROOT/sbin
install -p -m 755 %{SOURCE13} $RPM_BUILD_ROOT/sbin
install -p -m 755 %{SOURCE21} $RPM_BUILD_ROOT/sbin
install -p -m 644 %{SOURCE7} $RPM_BUILD_ROOT/lib/udev/rules.d/56-zfcp.rules
install -p -m 644 %{SOURCE12} $RPM_BUILD_ROOT/lib/udev/rules.d/56-dasd.rules

touch $RPM_BUILD_ROOT%{_sysconfdir}/{zfcp.conf,dasd.conf}

install -p -m 644 etc/sysconfig/dumpconf ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig
install -p -m 755 etc/init.d/dumpconf ${RPM_BUILD_ROOT}%{_initddir}/dumpconf

install -p -m 644 etc/sysconfig/mon_statd ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig
install -p -m 755 %{SOURCE19} ${RPM_BUILD_ROOT}%{_initddir}/mon_statd

install -p -m 644 etc/sysconfig/cpuplugd ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig
install -p -m 755 %{SOURCE18} ${RPM_BUILD_ROOT}%{_initddir}/cpuplugd

install -Dp -m 644 etc/udev/rules.d/*.rules ${RPM_BUILD_ROOT}/lib/udev/rules.d

# cmsfs tools must be available in /sbin
install -p -m 755 cmsfs-%{cmsfsver}/cmsfscat $RPM_BUILD_ROOT/sbin
install -p -m 755 cmsfs-%{cmsfsver}/cmsfslst $RPM_BUILD_ROOT/sbin
install -p -m 755 cmsfs-%{cmsfsver}/cmsfsvol $RPM_BUILD_ROOT/sbin
install -p -m 755 cmsfs-%{cmsfsver}/cmsfscp  $RPM_BUILD_ROOT/sbin
install -p -m 755 cmsfs-%{cmsfsver}/cmsfsck  $RPM_BUILD_ROOT/sbin
install -p -m 644 cmsfs-%{cmsfsver}/cmsfscat.8 $RPM_BUILD_ROOT%{_mandir}/man8
install -p -m 644 cmsfs-%{cmsfsver}/cmsfslst.8 $RPM_BUILD_ROOT%{_mandir}/man8
install -p -m 644 cmsfs-%{cmsfsver}/cmsfsvol.8 $RPM_BUILD_ROOT%{_mandir}/man8
install -p -m 644 cmsfs-%{cmsfsver}/cmsfscp.8  $RPM_BUILD_ROOT%{_mandir}/man8
install -p -m 644 cmsfs-%{cmsfsver}/cmsfsck.8  $RPM_BUILD_ROOT%{_mandir}/man8

# src_vipa
pushd src_vipa-%{vipaver}
make install LIBDIR=%{_libdir} SBINDIR=%{_bindir} INSTROOT=$RPM_BUILD_ROOT
popd

# install usefull headers for devel subpackage
mkdir -p $RPM_BUILD_ROOT%{_includedir}/%{name}
install -p -m 644 include/vtoc.h $RPM_BUILD_ROOT%{_includedir}/%{name}

# CPI
install -p -m 644 %{SOURCE11} ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig/cpi
install -p -m 755 %{SOURCE10} ${RPM_BUILD_ROOT}%{_initddir}/cpi

# device_cio_free
install -p -m 755 %{SOURCE14} ${RPM_BUILD_ROOT}/sbin
pushd ${RPM_BUILD_ROOT}/sbin
for lnk in dasd zfcp znet; do
    ln -sf device_cio_free ${lnk}_cio_free
done
popd
mkdir -p ${RPM_BUILD_ROOT}/lib/systemd/system
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/systemd/system/sysinit.target.wants
install -p -m 644 %{SOURCE15} ${RPM_BUILD_ROOT}/lib/systemd/system
pushd ${RPM_BUILD_ROOT}%{_sysconfdir}/systemd/system/sysinit.target.wants
ln -sf /lib/systemd/system/device_cio_free.service device_cio_free.service
popd

# ccw
mkdir -p ${RPM_BUILD_ROOT}/lib/udev/rules.d
install -p -m 755 %{SOURCE16} ${RPM_BUILD_ROOT}/lib/udev/ccw_init
install -p -m 644 %{SOURCE17} ${RPM_BUILD_ROOT}/lib/udev/rules.d/81-ccw.rules

# zipl.conf to be ghosted
touch ${RPM_BUILD_ROOT}%{_sysconfdir}/zipl.conf


%files
%doc README

#
# ************************* s390-tools base package  *************************
#
%package base
# src_vipa is CPL, the rest is GPLv2 or GPLv2+
License:        GPLv2 and GPLv2+ and CPL
Summary:        S390 base tools
Group:          System Environment/Base
Requires:       perl gawk sed coreutils
Requires:       sysfsutils
Requires:       sg3_utils
Requires:       ethtool
Requires(pre):   chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
BuildRequires:  ncurses-devel


%description base
s390 base tools. This collection provides the following utilities:
   * dasdfmt:
     Low-level format ECKD DASDs with the classical linux disk layout or the
     new z/OS compatible disk layout.

   * fdasd:
     Create or modify partitions on ECKD DASDs formatted with the z/OS
     compatible disk layout.

   * dasdview:
     Display DASD and VTOC information or dump the contents of a DASD to the
     console.

   * dasdinfo:
     Display unique DASD ID, either UID or volser.

   * udev rules:
     - 59-dasd.rules: rules for unique DASD device nodes created in /dev/disk/.

   * zipl:
     Make DASDs or tapes bootable for system IPL or system dump.

   * zgetdump:
     Retrieve system dumps from either tapes or DASDs.

   * qetharp:
     Read and flush the ARP cache on OSA Express network cards.

   * tape390_display:
     Display information on the message display facility of a zSeries tape
     device.

   * tape390_crypt:
     Control and query crypto settings for 3592 zSeries tape devices.

   * qethconf:
     bash shell script simplifying the usage of qeth IPA (IP address
     takeover), VIPA (Virtual IP address) and Proxy ARP.

   * dbginfo.sh:
     Shell script collecting useful information about the current system for
     debugging purposes.

   * zfcpdump:
     Dump tool to create system dumps on fibre channel attached SCSI disks.
     It is installed using the zipl command.

   * zfcpdump_v2:
     Version 2 of the zfcpdump tool. Now based on the upstream 2.6.26 Linux
     kernel.

   * ip_watcher:
     Provides HiperSockets Network Concentrator functionality.
     It looks for addresses in the HiperSockets and sets them as Proxy ARP
     on the OSA cards. It also adds routing entries for all IP addresses
     configured on active HiperSockets devices.
     Use start_hsnc.sh to start HiperSockets Network Concentrator.

   * tunedasd:
     Adjust tunable parameters on DASD devices.

   * vmconvert:
     Convert system dumps created by the z/VM VMDUMP command into dumps with
     LKCD format. These LKCD dumps can then be analyzed with the dump analysis
     tool lcrash.

   * vmcp:
     Allows Linux users to send commands to the z/VM control program (CP).
     The normal usage is to invoke vmcp with the command you want to
     execute. The response of z/VM is written to the standard output.

   * vmur:
     Allows to work with z/VM spool file queues (reader, punch, printer).

   * zfcpdbf:
     Display debug data of zfcp. zfcp provides traces via the s390 debug
     feature. Those traces are filtered with the zfcpdbf script, i.e. merge
     several traces, make it more readable etc.

   * scsi_logging_level:
     Create, get or set the logging level for the SCSI logging facility.

   * zconf:
     Set of scripts to configure and list status information of Linux for
     zSeries IO devices.
     - chccwdev:   Modify generic attributes of channel attached devices.
     - lscss:      List channel subsystem devices.
     - lsdasd:     List channel attached direct access storage devices (DASD).
     - lsqeth:     List all qeth-based network devices with their corresponding
                   settings.
     - lstape:     List tape devices, both channel and FCP attached.
     - lszfcp:     Shows information contained in sysfs about zfcp adapters,
                   ports and units that are online.
     - lschp:      List information about available channel-paths.
     - chchp:      Modify channel-path state.
     - lsluns:     List available SCSI LUNs depending on adapter or port.
     - lszcrypt:   Show Information about zcrypt devices and configuration.
     - chzcrypt:   Modify zcrypt configuration.
     - znetconf:   List and configure network devices for System z network
                   adapters.
     - cio_ignore: Query and modify the contents of the CIO device driver
                   blacklist.
     - lsmem:      Display the online status of the available memory.
     - chmem:      Set hotplug memory online or offline.

   * dumpconf:
     Allows to configure the dump device used for system dump in case a kernel
     panic occurs. This tool can also be used as an init script for etc/init.d.
     Prerequisite for dumpconf is a Linux kernel with the "dump on panic"
     feature.

   * ipl_tools:
     Tools set to configure and list reipl and shutdown actions.
     - lsreipl: List information of reipl device.
     - chreipl: Change reipl device settings.
     - lsshut:  List actions which will be done in case of halt, poff, reboot
                or panic.
     - chshut:  Change actions which should be done in case of halt, poff,
                reboot or panic.

    * cpi:
    Allows to set the system and sysplex names from the Linux guest to
    the HMC/SE using the Control Program Identification feature.

For more information refer to the following publications:
   * "Device Drivers, Features, and Commands" chapter "Useful Linux commands"
   * "Using the dump tools"

%post base
/sbin/chkconfig --add dumpconf
/sbin/chkconfig --add cpi

%preun base
if [ $1 = 0 ]; then
        # not for updates
        /sbin/service dumpconf stop > /dev/null 2>&1
        /sbin/chkconfig --del dumpconf
        /sbin/service cpi stop > /dev/null 2>&1
        /sbin/chkconfig --del cpi
fi
:

%files base
%doc README
%doc LICENSE
/sbin/zipl
/sbin/dasdfmt
/sbin/dasdinfo
/sbin/dasdstat
/sbin/dasdview
/sbin/fdasd
/sbin/chccwdev
/sbin/chchp
/sbin/chzcrypt
/sbin/cio_ignore
/sbin/lschp
/sbin/lscss
/sbin/lsdasd
/sbin/lsqeth
/sbin/lsscm
/sbin/lstape
/sbin/lszcrypt
/sbin/lszfcp
/sbin/scsi_logging_level
/sbin/zfcpdbf
/sbin/qetharp
/sbin/qethconf
/sbin/qethqoat
/sbin/tape390_display
/sbin/tape390_crypt
/sbin/ttyrun
/sbin/tunedasd
/sbin/vmcp
/sbin/zgetdump
/sbin/znetconf
/sbin/dbginfo.sh
%{_sbindir}/lsluns
%{_sbindir}/lsmem
%{_sbindir}/lsreipl
%{_sbindir}/lsshut
%{_sbindir}/chmem
%{_sbindir}/chreipl
%{_sbindir}/chshut
%{_sbindir}/ip_watcher.pl
%{_sbindir}/start_hsnc.sh
%{_sbindir}/vmur
%{_sbindir}/xcec-bridge
%{_sbindir}/hyptop
%{_bindir}/vmconvert
%{_initddir}/dumpconf
%ghost %config(noreplace) %{_sysconfdir}/zipl.conf
%config(noreplace) %{_sysconfdir}/sysconfig/dumpconf
/lib/s390-tools
%{_mandir}/man1/dbginfo.sh.1*
%{_mandir}/man1/zfcpdbf.1*
%{_mandir}/man4/prandom.4*
%{_mandir}/man5/zipl.conf.5*
%{_mandir}/man8/chccwdev.8*
%{_mandir}/man8/chchp.8*
%{_mandir}/man8/chmem.8*
%{_mandir}/man8/chreipl.8*
%{_mandir}/man8/chshut.8*
%{_mandir}/man8/chzcrypt.8*
%{_mandir}/man8/cio_ignore.8*
%{_mandir}/man8/dasdfmt.8*
%{_mandir}/man8/dasdinfo.8*
%{_mandir}/man8/dasdstat.8*
%{_mandir}/man8/dasdview.8*
%{_mandir}/man8/dumpconf.8*
%{_mandir}/man8/fdasd.8*
%{_mandir}/man8/hyptop.8*
%{_mandir}/man8/lschp.8*
%{_mandir}/man8/lscss.8*
%{_mandir}/man8/lsdasd.8*
%{_mandir}/man8/lsmem.8*
%{_mandir}/man8/lsluns.8*
%{_mandir}/man8/lsqeth.8*
%{_mandir}/man8/lsreipl.8*
%{_mandir}/man8/lsscm.8*
%{_mandir}/man8/lsshut.8*
%{_mandir}/man8/lstape.8*
%{_mandir}/man8/lszcrypt.8*
%{_mandir}/man8/lszfcp.8*
%{_mandir}/man8/qetharp.8*
%{_mandir}/man8/qethconf.8*
%{_mandir}/man8/qethqoat.8*
%{_mandir}/man8/tape390_crypt.8*
%{_mandir}/man8/tape390_display.8*
%{_mandir}/man8/ttyrun.8*
%{_mandir}/man8/tunedasd.8*
%{_mandir}/man8/vmconvert.8*
%{_mandir}/man8/vmcp.8*
%{_mandir}/man8/vmur.8*
%{_mandir}/man8/zgetdump.8*
%{_mandir}/man8/znetconf.8*
%{_mandir}/man8/zipl.8*

# Additional Redhat specific stuff
/boot/tape0
%{_sysconfdir}/profile.d/s390.csh
%{_sysconfdir}/profile.d/s390.sh
%ghost %config(noreplace) %{_sysconfdir}/dasd.conf
%ghost %config(noreplace) %{_sysconfdir}/zfcp.conf
%{_initddir}/cpi
%config(noreplace) %{_sysconfdir}/sysconfig/cpi
/sbin/dasdconf.sh
/sbin/zfcpconf.sh
/sbin/dasd_cio_free
/sbin/device_cio_free
/sbin/zfcp_cio_free
/sbin/znet_cio_free
/sbin/normalize_dasd_arg
/lib/systemd/system/device_cio_free.service
%{_sysconfdir}/systemd/system/sysinit.target.wants/device_cio_free.service
/lib/udev/ccw_init
/lib/udev/rules.d/40-z90crypt.rules
/lib/udev/rules.d/56-zfcp.rules
/lib/udev/rules.d/56-dasd.rules
/lib/udev/rules.d/59-dasd.rules
/lib/udev/rules.d/60-readahead.rules
/lib/udev/rules.d/81-ccw.rules

# src_vipa
%{_bindir}/src_vipa.sh
%{_libdir}/src_vipa.so
%{_mandir}/man8/src_vipa.8*

#
# *********************** s390-tools osasnmpd package  ***********************
#
%package osasnmpd
License:        GPLv2+
Summary:        SNMP sub-agent for OSA-Express cards
Group:          System Environment/Daemons
Requires:       net-snmp
Requires:       psmisc
BuildRequires:  net-snmp-devel

%description osasnmpd
UCD-SNMP/NET-SNMP sub-agent implementing MIBs provided by OSA-Express
features Fast Ethernet, Gigabit Ethernet, High Speed Token Ring and
ATM Ethernet LAN Emulation in QDIO mode.

%files osasnmpd
%{_sbindir}/osasnmpd
/lib/udev/rules.d/57-osasnmpd.rules
%{_mandir}/man8/osasnmpd.8*

#
# *********************** s390-tools mon_statd package  **********************
#
%package mon_statd
License:         GPLv2
Summary:         Monitoring daemons for Linux in z/VM
Group:           System Environment/Daemons
Requires:        coreutils
Requires(pre):   chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts

%description mon_statd
Monitoring daemons for Linux in z/VM:

  - mon_fsstatd: Daemon that writes file system utilization data to the
                 z/VM monitor stream.

  - mon_procd:   Daemon that writes process information data to the z/VM
                 monitor stream.

%post mon_statd
/sbin/chkconfig --add mon_statd

%preun mon_statd
if [ $1 = 0 ]; then
        # not for updates
        /sbin/service mon_statd stop > /dev/null 2>&1
        /sbin/chkconfig --del mon_statd
fi
:

%files mon_statd
%{_sbindir}/mon_fsstatd
%{_sbindir}/mon_procd
%config(noreplace) %{_sysconfdir}/sysconfig/mon_statd
%{_initddir}/mon_statd
%{_mandir}/man8/mon_fsstatd.8*
%{_mandir}/man8/mon_procd.8*

#
# *********************** s390-tools cpuplugd package  ***********************
#
%package cpuplugd
License:         GPLv2+
Summary:         Daemon that manages CPU and memory resources
Group:           System Environment/Daemons
Requires:        coreutils
Requires(pre):   chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts

%description cpuplugd
Daemon that manages CPU and memory resources based on a set of rules.
Depending on the workload CPUs can be enabled or disabled. The amount of
memory can be increased or decreased exploiting the CMM1 feature.

%post cpuplugd
/sbin/chkconfig --add cpuplugd

%preun cpuplugd
if [ $1 = 0 ]; then
        # not for updates
        /sbin/service cpuplugd stop > /dev/null 2>&1
        /sbin/chkconfig --del cpuplugd
fi
:

%files cpuplugd
%{_initddir}/cpuplugd
%config(noreplace) %{_sysconfdir}/sysconfig/cpuplugd
%{_sbindir}/cpuplugd
%{_mandir}/man5/cpuplugd.conf.5*
%{_mandir}/man8/cpuplugd.8*

#
# *********************** s390-tools ziomon package  *************************
#
%package ziomon
License:        GPLv2
Summary:        S390 ziomon tools
Group:          Applications/System
Requires:       perl lsscsi coreutils blktrace >= 1.0.1

%description ziomon
Tool set to collect data for zfcp performance analysis and report.

%files ziomon
%{_sbindir}/ziomon
%{_sbindir}/ziomon_fcpconf
%{_sbindir}/ziomon_mgr
%{_sbindir}/ziomon_util
%{_sbindir}/ziomon_zfcpdd
%{_sbindir}/ziorep_config
%{_sbindir}/ziorep_traffic
%{_sbindir}/ziorep_utilization
%{_mandir}/man8/ziomon.8*
%{_mandir}/man8/ziomon_fcpconf.8*
%{_mandir}/man8/ziomon_mgr.8*
%{_mandir}/man8/ziomon_util.8*
%{_mandir}/man8/ziomon_zfcpdd.8*
%{_mandir}/man8/ziorep_config.8*
%{_mandir}/man8/ziorep_traffic.8*
%{_mandir}/man8/ziorep_utilization.8*

#
# *********************** s390-tools iucvterm package  *************************
#
%package iucvterm
License:        GPLv2
Summary:        z/VM IUCV terminal applications
Group:          Applications/System
Requires(pre):  shadow-utils
Requires(post): grep
Requires(postun): grep
BuildRequires:  gettext

%description iucvterm
A set of applications to provide terminal access via the z/VM Inter-User
Communication Vehicle (IUCV). The terminal access does not require an
active TCP/IP connection between two Linux guest operating systems.

- iucvconn:  Application to establish a terminal connection via z/VM IUCV.
- iucvtty:   Application to provide terminal access via z/VM IUCV.
- ts-shell:  Terminal server shell to authorize and control IUCV terminal
             connections for individual Linux users.

%pre iucvterm
# check for ts-shell group and create it
getent group ts-shell > /dev/null || groupadd -r ts-shell

%post iucvterm
# /etc/shells is provided by "setup"
grep -q '^/usr/bin/ts-shell$' /etc/shells \
    || echo "/usr/bin/ts-shell" >> /etc/shells

%postun iucvterm
if [ $1 = 0 ]
then
    # remove ts-shell from /etc/shells on uninstall
    grep -v '^/usr/bin/ts-shell$' /etc/shells > /etc/shells.ts-new
    mv /etc/shells.ts-new /etc/shells
    chmod 0644 /etc/shells
fi

%files iucvterm
%dir %{_sysconfdir}/iucvterm
%config(noreplace) %attr(0640,root,ts-shell) %{_sysconfdir}/iucvterm/ts-audit-systems.conf
%config(noreplace) %attr(0640,root,ts-shell) %{_sysconfdir}/iucvterm/ts-authorization.conf
%config(noreplace) %attr(0640,root,ts-shell) %{_sysconfdir}/iucvterm/ts-shell.conf
%config(noreplace) %attr(0640,root,ts-shell) %{_sysconfdir}/iucvterm/unrestricted.conf
%{_bindir}/iucvconn
%{_bindir}/iucvtty
%{_bindir}/ts-shell
%{_sbindir}/chiucvallow
%{_sbindir}/lsiucvallow
%dir %attr(2770,root,ts-shell) /var/log/ts-shell
%doc iucvterm/doc/ts-shell
%{_mandir}/man1/iucvconn.1*
%{_mandir}/man1/iucvtty.1*
%{_mandir}/man1/ts-shell.1*
%{_mandir}/man7/af_iucv.7*
%{_mandir}/man8/chiucvallow.8*
%{_mandir}/man9/hvc_iucv.9*

#
# *********************** cmsfs package  ***********************
#
%package cmsfs
License:        GPLv2
Summary:        CMS file system tools
Group:          System Environment/Base
URL:            http://www.casita.net/pub/cmsfs/cmsfs.html
# Requires:

%description cmsfs
This package contains the CMS file system tools.

%files cmsfs
/sbin/cmsfscat
/sbin/cmsfsck
/sbin/cmsfscp
/sbin/cmsfslst
/sbin/cmsfsvol
%{_mandir}/man8/cmsfscat.8*
%{_mandir}/man8/cmsfsck.8*
%{_mandir}/man8/cmsfscp.8*
%{_mandir}/man8/cmsfslst.8*
%{_mandir}/man8/cmsfsvol.8*

#
# *********************** cmsfs-fuse package  ***********************
#
%package cmsfs-fuse
License:        GPLv2
Summary:        CMS file system based on FUSE
Group:          System Environment/Base
BuildRequires:  fuse-devel
Requires:       fuse

%description cmsfs-fuse
This package contains the CMS file system based on FUSE.

%files cmsfs-fuse
%dir %{_sysconfdir}/cmsfs-fuse
%config(noreplace) %{_sysconfdir}/cmsfs-fuse/filetypes.conf
%{_bindir}/cmsfs-fuse
%{_mandir}/man1/cmsfs-fuse.1*

#
# *********************** devel package  ***********************
#
%package devel
License:        GPLv2
Summary:        Development files
Group:          Development/Libraries

%description devel
User-space development files for the s390/s390x architecture.

%files devel
%{_includedir}/%{name}


%changelog
* Wed Mar 05 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-12
- udpdate the device_cio_free script for #1054691
- Resolves: #1054691

* Tue Mar 04 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-11
- fix zFCP device discovery in anaconda GUI (#1054691)
- Resolves: #1054691

* Mon Feb 10 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-10
- znetconf: Allow for 16-char network interface names (#1062285)
- qetharp: Allow for 16-char network interface names (#1062250)
- Resolves: #1062285, #1062250

* Mon Feb 03 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-9
- znetconf,lsqeth: Allow for 16-char network interface name (#1060303)
- Resolves: #1060303

* Wed Jan 29 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-8
- zipl: Fix zfcpdump "struct job_ipl_data" initialization (#1058856)
- Resolves: #1058856

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 2:1.23.0-7
- Mass rebuild 2014-01-24

* Wed Jan 15 2014 Dan Horák <dan[at]danny.cz> - 2:1.23.0-6
- zipl: fix segmentation fault in automenu array (#1017541)
- zfcpconf.sh: check current online state before setting zfcp device online (#1042496)
- Resolves: #1017541, #1042496

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 2:1.23.0-5
- Mass rebuild 2013-12-27

* Tue Nov 19 2013 Dan Horák <dan[at]danny.cz> - 2:1.23.0-4
- dbginfo.sh: enhancements for script execution and man page (#1031144)
- dbginfo.sh: avoid double data collection (#1032068)
- Resolves: #1031144, #1032068

* Wed Nov 06 2013 Dan Horák <dan[at]danny.cz> - 2:1.23.0-3
- build daemons hardened (#881250)
- zipl: Use "possible_cpus" kernel parameter (#1016180)
- Resolves: #881250, #1016180

* Wed Aug 21 2013 Dan Horák <dan[at]danny.cz> - 2:1.23.0-2
- dbginfo.sh: Avoiding exclusion list for pipes in sysfs (#996732)
- zipl: Fix zipl "--force" option for DASD multi-volume dump (#997361)

* Wed Jul 23 2013 Dan Horák <dan[at]danny.cz> - 2:1.23.0-1
- rebased to 1.23 (#804774)

* Wed Jul 17 2013 Dan Horák <dan[at]danny.cz> - 2:1.20.0-5.1
- rebuilt for new net-snmp (#985251)

* Wed Jun 05 2013 Dan Horák <dan[at]danny.cz> - 2:1.20.0-5
- update with patches from RHEL-6
- rebase zIPL to 1.21 to fix booting from FBA DASD (#970859)

* Tue May 21 2013 Dan Horák <dan[at]danny.cz> - 2:1.20.0-4
- drop the libzfcphbaapi subpackage as it is moved to its own package (#963670)
- update the zfcp udev rules (#958197)
- fix runtime dependencies for osasnmpd (#965413)

* Wed Mar 27 2013 Dan Horák <dan[at]danny.cz> - 2:1.20.0-3
- disable libzfcphbaapi subpackage, fails to build with recent kernels

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:1.20.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Dec 19 2012 Dan Horák <dan[at]danny.cz> - 2:1.20.0-1
- updated to 1.20.0 (#804774)

* Thu Nov 22 2012 Dan Horák <dan[at]danny.cz> - 2:1.19.0-4
- clean BuildRequires a bit

* Mon Sep 16 2012 Dan Horák <dan[at]danny.cz> - 2:1.19.0-3
- zipl: Flush disk buffers before installing IPL record (#857814)

* Mon Aug 27 2012 Dan Horák <dan[at]danny.cz> 2:1.19.0-2
- add support for CEX4 devices to chzcrypt/lszcrypt (#847092)

* Mon Aug 27 2012 Dan Horák <dan[at]danny.cz> 2:1.19.0-1
- updated to 1.19.0 (#804774)
- fixed syntax in s390.sh script (#851096)
- spec cleanup

* Tue Aug 21 2012 Dan Horák <dan[at]danny.cz> 2:1.17.0-1
- updated to 1.17.0
- add support for new storage device on System z (#847086)

* Thu Aug 16 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-11
- fix libzfcphbaapi for recent kernels

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:1.16.0-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri May 25 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-9
- improve DASD parameters handling in normalize_dasd_arg (#824807)

* Wed May 23 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-8
- add normalize_dasd_arg script (#823078)

* Mon May 14 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-7
- ethtool is required by lsqeth (#821421)

* Fri May 11 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-6
- updated the Fedora patch set - no vol_id tool in udev (#819530)

* Fri May  4 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-5
- zipl.conf must be owned by s390utils-base (#818877)

* Tue Apr 17 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-4
- install the z90crypt udev rule (moved here from the udev package)

* Tue Apr 10 2012 Dan Horák <dan[at]danny.cz> 2:1.16.0-3
- include fixed ccw_init and updated device_cio_free

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:1.16.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Dec 15 2011 Dan Horák <dan[at]danny.cz> 2:1.16.0-1
- rebased to 1.16.0

* Tue Aug 16 2011 Dan Horák <dan[at]danny.cz> 2:1.14.0-1
- rebased to 1.14.0

* Wed Apr 27 2011 Dan Horák <dan[at]danny.cz> 2:1.8.2-32
- updated ccw udev rules
- converted cio_free_device from an upstart job to systemd unit (jstodola)
- mon_statd: switch to using udevadm settle (#688140)
- cpuplugd: Fix incorrect multiplication in rules evaluation (#693365)
- cmsfs-fuse: Delete old file if renaming to an existing file (#690505)
- cmsfs-fuse: Enlarge fsname string (#690506)
- cmsfs-fuse: Unable to use cmsfs-fuse if $HOME is not set (#690514)
- hyptop: Prevent interactive mode on s390 line mode terminals (#690810)

* Fri Mar 18 2011 Dan Horák <dhorak@redhat.com> 2:1.8.2-31
- mon_statd: switch to using udevadm settle (#688140)
- hyptop: Fix man page typo for "current weight" (#684244)
- fdasd: buffer overflow when writing to read-only device (#688340)
- cmsfs-fuse: fix read and write errors in text mode (#680465)
- cmsfs-fuse needs fuse (#631546)
- dumpconf: Add DELAY_MINUTES description to man page (#676706)
- iucvterm scriptlet need shadow-utils (#677247)
- use lower-case in udev rules (#597360)
- add support for the 1731/02 OSM/OSX network device (#636849)
- xcec-bridge: fix multicast forwarding (#619504)
- ziomon: wrong return codes (#623250)
- qethconf: process devices with non-zero subchannel (#627692)
- wait for completion of any pending actions affecting device (#631527)
- add infrastructure code for new features (#631541)
- hyptop: Show hypervisor performance data on System z (#631541)
- cmsfs-fuse: support for CMS EDF filesystems via fuse (#631546)
- lsmem/chmem: Tools to manage memory hotplug (#631561)
- dumpconf: Prevent re-IPL loop for dump on panic (#633411)
- ttyrun: run a program if a terminal device is available (#633420)
- zgetdump/zipl: Add ELF dump support (needed for makedumpfile) (#633437)
- znetconf: support for OSA CHPID types OSX and OSM (#633534)
- iucvtty: do not specify z/VM user ID as argument to login -h (#636204)
- tunedasd: add new option -Q / --query_reserve (#644935)
- fdasd/dasdfmt: fix format 7 label (#649787)
- cpuplugd: cmm_pages not set and restored correctly (#658517)
- lsluns: Fix LUN reporting for SAN volume controller (SVC) (#659828)
- lsluns: Accept uppercase and lowercase hex digits (#660361)
- cmsfs: use detected filesystem block size (#651012)
- device_cio_free: use the /proc/cio_settle interface when waiting for devices
- libzfcphbaapi library needs kernel-devel during build and thus is limited to s390x
- libzfcphbaapi library rebased to 2.1 (#633414)
- new zfcp tools added (#633409)

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:1.8.2-30
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Jul 13 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-29
- lsluns: uninitialized value on adapter offline (#611795)
- zfcpdbf: Fix 'Use of uninitialized value' and output issues (#612622)

* Wed Jul  7 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-28
- fix linking with --no-add-needed

* Tue Jun 29 2010 Dan Horák <dhorak@redhat.com> 2:1.8.2-27
- make znet_cio_free work also when no interface config files exists (#609073)
- fix --dates option in zfcpdbf (#609092)

* Mon Jun 28 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-26
- follow symlinks in ziorep (#598574)
- do not restrict group names to be alphanumeric in ts-shell (#598641)
- znetconf --drive|-d option returning 'unknown driver' for qeth (#601846)
- fix stack overwrite in cpuplugd (#601847)
- fix cmm_min/max limit checks in cpuplugd (#606366)
- set cpu_min to 1 by default in cpuplugd (#606416)
- build with -fno-strict-aliasing (#599396)
- remove reference to z/VM from the cpi initscript (#601753)
- fix return values for the mon_statd initscript (#606805)
- ignore backup and similar config files in device_cio_free (#533494)

* Fri May 28 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-25
- fixed device_cio_free command line handling (#595569)

* Thu May 20 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-24
- added a check for the length of the parameters line (#594031)

* Wed May 19 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-23
- make ccw_init compatible with posix shell (#546615)

* Wed May  5 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-22
- scripts can't depend on stuff from /usr (#587364)

* Mon May  3 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-21
- updated patch for the "reinitialize array in lsqeth" issue (#587757)

* Fri Apr 30 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-20
- updated lsdasd man page (#587044)
- reinitialize array in lsqeth (#587599)

* Wed Apr 28 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-19
- fixed mismatch between man and -h in chshut (#563625)
- use the merged ccw_init script (#533494, #561814)

* Thu Apr 22 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-18
- lsluns utility from the base subpackage requires sg3_utils

* Wed Apr 21 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-17
- updated device_cio_free script (#576015)

* Wed Mar 31 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-16
- updated device_cio_free upstart config file (#578260)
- fix multipathing in ziomon (#577318)

* Mon Mar 29 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-15
- remove check for ziorep_config availability (#576579)
- install upstart event file into /etc/init (#561339)
- device_cio_free updates
    - don't use basename/dirname
    - correctly parse /etc/ccw.conf (#533494)

* Mon Mar 22 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-14
- don't use memory cgroups in zfcpdump kernel (#575183)
- fix df usage in ziomon (#575833)

* Thu Mar 11 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-13
- dropped dependency on redhat-lsb (#542702)

* Wed Mar 10 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-12
- run device_cio_free on startup (#561339)
- use hex index for chpidtype table in znetconf (#561056)
- handle status during IPL SSCH (#559250)
- don't show garbage in vmconvert's progress bar (#567681)
- don't print enviroment when there are no devices to wait for (#570763)
- fix zfcp dump partition error (#572313)
- switched to new initscripts for cpuplugd and fsstatd/procd (#524218, #524477)

* Tue Feb 16 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-11
- moved ccw udev stuff from initscripts to s390utils
- updated ccw_init with delay loops and layer2 handling (#561926)

* Fri Jan 22 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-10.1
- really update zfcpconf.sh script from dracut

* Wed Jan 20 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-10
- fixed return codes in ziorep (#556849)
- fixed return code in lstape (#556910)
- fixed reading the size of /proc/sys/vm/cmm_pages in cpuplugd (#556911)
- support new attributes in lsqeth (#556915)

* Wed Jan 13 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-9
- updated device_cio_free script (#533494)
- fixed uppercase conversion in lscss (#554768)

* Fri Jan  8 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-8
- updated device_cio_free script (#533494)

* Fri Jan  8 2010 Dan Horák <dan[at]danny.cz> 2:1.8.2-7
- updated device_cio_free script (#533494)

* Tue Dec 22 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-6.1
- fixed return value in cpi initscript (#541389)

* Tue Dec 22 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-6
- fixed return value in cpi initscript (#541389)
- updated zfcpconf.sh script from dracut
- added device-mapper support into zipl (#546280)
- added missing check and print NSS name in case an NSS has been IPLed (#546297)
- added device_cio_free script and its symlinks (#533494)
- added qualified return codes and further error handling in znetconf (#548487)

* Fri Nov 13 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-5
- added multiple fixes from IBM (#533955, #537142, #537144)

* Thu Nov 12 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-4
- added udev rules and script for dasd initialization (#536966)
- added ghosted zfcp and dasd config files, fixes their ownership on the system
- fixed upgrade path for libzfcphbaapi-devel subpackage

* Mon Nov  9 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-3
- added files for the CPI feature (#463282)
- built lib-zfcp-hbaabi library as vendor lib, switched from -devel (no devel content now) to -docs subpackage (#532707)

* Fri Oct 30 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-2
- install dasd udev rules provided by the s390-tools
- added patch for setting readahead value

* Thu Oct  8 2009 Dan Horák <dan[at]danny.cz> 2:1.8.2-1
- added patch for improving mon_statd behaviour
- rebased to 1.8.2

* Fri Oct  2 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-8
- really changed ramdisk load address (#526339)
- change the required and optional subpackages for the meta package

* Wed Sep 30 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-7
- changed ramdisk load address (#526339)
- updated zfcpconf.sh script to new sysfs interface (#526324)
- added 1.8.1 fixes from IBM (#525495)

* Fri Sep 25 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-6
- fix issues in lib-zfcp-hbaapi with a patch

* Thu Sep 24 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-5
- drop support for Fedora < 10

* Thu Sep 24 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-4
- fixed string overflow in vtoc_volume_label_init (#525318)

* Thu Sep  3 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-3
- create devel subpackage with some useful headers
- preserving timestamps on installed files

* Wed Aug 26 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-2
- Fix byte check for disk encryption check in lsluns (#510032)
- Fix cmm configuration file value initialization parser in cpuplugd (#511379)
- Check only ZFCP devices in lszfcp (#518669)

* Mon Jun 29 2009 Dan Horák <dan[at]danny.cz> 2:1.8.1-1
- update to 1.8.1
- drop upstreamed patches
- create iucvterm subpackage
- update src_vipa locations patch
- install cmsfs tools into /sbin
- add post 1.8.1 fixes from IBM

* Fri Apr 17 2009 Dan Horák <dan[at]danny.cz> 2:1.8.0-6
- fix build with newer kernels

* Wed Mar 25 2009 Dan Horák <dan[at]danny.cz> 2:1.8.0-5
- reword the summaries a bit
- add downloadable URLs for Sources
- fix CFLAGS usage

* Fri Mar 13 2009 Dan Horák <dan[at]danny.cz> 2:1.8.0-4
- next round of clean-up for compliance with Fedora

* Sun Mar  8 2009 Dan Horák <dan[at]danny.cz> 2:1.8.0-3
- little clean-up for compliance with Fedora

* Fri Dec 12 2008 Hans-Joachim Picht <hans@linux.vnet.ibm.com> 2:1.8.0-2
- Adapted package for F9

* Tue Dec 8 2008 Michael Holzheu <michael.holzheu@de.ibm.com> 2:1.8.0-1
- Changed spec file to create sub packages
- Updated to zfcphbaapi version 2.0

* Tue Oct 28 2008 Dan Horák <dan[at]danny.cz> 2:1.7.0-4
- disable build-id feature in zipl (#468017)

* Wed Sep 24 2008 Dan Horák <dan[at]danny.cz> 2:1.7.0-3
- drop the mon_tools patch (mon_statd service starts both mon_procd and mon_fsstatd since 1.7.0)

* Thu Aug 28 2008 Dan Horák <dan[at]danny.cz> 2:1.7.0-2
- preserve timestamps on installed files
- add proper handling of initscripts
- fix permissions for some files

* Tue Aug 12 2008 Dan Horák <dan[at]danny.cz> 2:1.7.0-1
- update to s390-tools 1.7.0, src_vipa 2.0.4 and cmsfs 1.1.8c
- rebase or drop RHEL5 patches

* Fri Jul 25 2008 Dan Horák <dhorak@redhat.com> 2:1.5.3-19.el5
- fix use "vmconvert" directly on the vmur device node (#439389)
- fix the Linux Raid partition type is not retained when changed through fdasd (#445271)
- include missing files into the package (#442584)
- Resolves: #439389, #445271, #442584

* Fri Jul 25 2008 Dan Horák <dhorak@redhat.com> 2:1.5.3-18.el5
- split the warnings patch into s390-tools and cmsfs parts
- mismatch between installed /etc/zfcp.conf and zfcpconf.sh expected format (#236016)
- dbginfo.sh exits before running all tests and drops errors (#243299)
- updates for cleanup SCSI dumper code for upstream integration - tool (#253118)
- fix segfault when using LD_PRELOAD=/usr/lib64/src_vipa.so (#282751)
- add support for timeout parameter in /etc/zipl.conf (#323651)
- fixes not listing all the dasds passed as arguments to lsdasd command (#369891)
- fix for zipl fail when section is specified and target is not repeated for all sections (#381201)
- fix for dasdview -s option fails to ignore the garbage value passed (#412951)
- update documentation for zfcpdump (#437477)
- update documentation for lsqeth (#455908)
- Resolves: #236016, #243299, #253118, #282751, #323651, #369891, #381201, #412951, #437477, #455908

* Fri Mar 28 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-17.el5
- Fix error messages and proc/0 entry are not handled correctly (#438819)

* Wed Feb 06 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-16.el5
- Fixed a build problem with the mon_tools patch (#253029)

* Mon Feb 04 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-14.el5
- Added zfcpdump kernel symlink to dumpconf init script (#430550)

* Fri Jan 18 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-13.el5
- Fix tape390_crypt query shows wrong msg 'Kernel does not support tape encryption' (#269181)

* Wed Jan 16 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-12.el5
- Add System z guest file system size in Monitor APPLDATA (#253029)
- Add Dynamic CHPID reconfiguration via SCLP - tools (#253076)
- Add z/VM unit-record device driver - tools (#253078)
- Cleanup SCSI dumper code for upstream integration - tool (#253118)

* Tue Jan 08 2008 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-11.el5
- Fix installer LVM partitions that show up as "unknown" in fdasd (#250176)
- Fixed zfcpconf.sh failure if / and /usr are separated (#279201)

* Mon Sep 24 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.14
- Added missing openssl-devel buildrequires (#281361)

* Thu Aug 23 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.13
- Last updage for -t parameter patch (#202086)

* Tue Aug 14 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.12
- Fix handling of external timer interrupts (#250352)

* Tue Jul 31 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.11
- Update fix for -t parameter for image operations (#202086)

* Fri Jul 27 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.10
- Fixed udev regression from RHEL 4 with /dev/dasd/ (#208189)
- Fixed missing -d option for zgetdump (#228094)

* Thu Jun 28 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.9
- Fix optional -t parameter for image operations (#202086)

* Wed Jun 27 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.8
- Fix wrong manpage (#202250)
- Fix zfcp devices not showing up after boot (#223569)
- Fix help menu of lsqeth showing wrong file (#225159)
- Add tape encryption userspace tool (#228080)
- Add dump on panic initscript and sysconf (#228094)
- Fix a off-by-one error in zfcpdbf (#230527)
- Fix zipl aborting with floating point exception if the target specified is a logical volume (#231240)
- Fix boot menu use wrong conversion table for input on LPAR (#240399)

* Mon Jan 22 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.6
- Fixed problem with invisible zfcp devices after boot (#223569)

* Mon Jan 15 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.5
- Extended fix for automenu bug (#202086)

* Thu Jan 11 2007 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.4
- Updated dbginfo.sh patch to final fix from IBM (#214805)

* Wed Nov 29 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.3
- Fixed problem with missing debugfs for dbginfo.sh (#214805)

* Thu Nov 09 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.2
- Fixed lszfcp bug related to sysfsutils (#210515)

* Tue Nov 07 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10.el5.1
- Removed wrong additional $ in src_vipa.sh (#213395)
- Release and Buildroot specfile fixes

* Wed Sep 13 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-10
- Needed to bump release

* Tue Sep 12 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-9
- Added libsysfs requirement (#201863)
- Fixed zipl problem with missing default target for automenus (#202086)

* Thu Aug 10 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-8
- Added missing sysfsutils requirement for lszfcp (#201863)

* Tue Jul 25 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-7
- Included zfcpdbf, dbginfo.sh and the man1 manpages to package (#184812)

* Tue Jul 18 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-6
- Disabled sysfs support due to API changes in sysfs-2.0.0

* Fri Jul 14 2006 Karsten Hopp <karsten@redhat.de> 2:1.5.3-5
- buildrequire net-snmp-devel

* Fri Jul 14 2006 Jesse Keating <jkeating@redhat.com> - 2:1.5.3-4
- rebuild
- Add missing br libsysfs-devel, indent, zlib-devel

* Wed May 17 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.3-1
- Made src_vipa build on current toolchain again

* Tue May 16 2006 Phil Knirsch <pknirsch@redhat.com>
- Update to s390-tools-1.5.3 from IBM
- Included vmconvert
- Dropped obsolete asm patch

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 2:1.5.0-2.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Mon Jan 30 2006 Phil Knirsch <pknirsch@redhat.com> 2:1.5.0-2
- Fixed problem with s390-tools-1.5.0-fdasd-raid.patch
- Don't try to remove the non empty _bindir
- Some more install cleanups

* Thu Jan 26 2006 Phil Knirsch <pknirsch@redhat.com>
- Fixed some .macro errors in zipl/boot

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Thu Oct 20 2005 Phil Knirsch <pknirsch@redhat.com> 2:1.5.0-1
- Large update from 1.3.2 to 1.5.0
- Include osasnmpd and vmcp now by default

* Tue Sep 06 2005 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-7
- Fixed a couple of code bugs (#143808)

* Fri Jul 29 2005 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-6
- Corrected filelist for libdir to only include *.so files

* Tue Jun 21 2005 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-5
- Added src_vipa to s390utils

* Wed Mar 02 2005 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-4
- bump release and rebuild with gcc 4

* Tue Oct 26 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-3
- Put binaries for system recovery in /sbin again.

* Fri Oct 15 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.2-1
- Update to s390-tools-1.3.2
- Added qetharp, qethconf, ip_watcher, tunedasd and various other tools to
  improve functionality on s390(x).

* Wed Oct 06 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.1-7
- Made the raid patch less verbose (#129656)

* Thu Sep 16 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.1-6
- Added prompt=1 and timeout=15 to automatically generated menu

* Tue Aug 31 2004 Karsten Hopp <karsten@redhat.de> 2:1.3.1-5
- install zfcpconf.sh into /sbin

* Tue Aug 24 2004 Karsten Hopp <karsten@redhat.de> 2:1.3.1-4 
- add zfcpconf.sh to read /etc/zfcp.conf and configure the zfcp
  devices

* Thu Jun 24 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.1-3
- Fixed another automenu bug with dumpto and dumptofs (#113204).

* Thu Jun 17 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.1-2
- Fixed automenu patch.
- Fixed problem with installation from tape (#121788).

* Wed Jun 16 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.3.1-1
- Updated to latest upstream version s390-tools-1.3.1

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Jun 07 2004 Karsten Hopp <karsten@redhat.com>
- add cmsfs utils

* Tue Mar 02 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Thu Feb 19 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.2.4-4
- Fixed rebuilt on fc2.

* Thu Feb 19 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.2.4-3
- Fixed automenu patch, was allocating 1 line to little.

* Mon Feb 16 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.2.4-2
- rebuilt

* Mon Feb 16 2004 Phil Knirsch <pknirsch@redhat.com> 2:1.2.4-1
- Updated to latest developerworks release 1.2.4
- Disabled zfcpdump build until i find a way to build it as none-root.

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com> 2:1.2.3-3
- rebuilt

* Thu Dec 04 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.3-2
- Fixed zfcpdump build.

* Fri Nov 28 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.3-1
- New bugfix release 1.2.3 came out today, updated again.

* Wed Nov 26 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.2-1
- Updated to latest Developerworks version 1.2.2
- Cleaned up specfile and patches a little.

* Wed Nov 12 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-4.1
- rebuilt

* Wed Nov 12 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-4
- Another fix for the new automenu patch. Target was an optional parameter in
  old s390utils, provided compatibility behaviour.

* Mon Oct 20 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-3.1
- rebuilt

* Mon Oct 20 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-3
- Small fix for the new automenu patch, default section didn't work correctly

* Mon Oct 20 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-2.1
- rebuilt

* Fri Oct 17 2003 Phil Knirsch <pknirsch@redhat.com> 2:1.2.1-2
- Patched new zipl to be backwards compatible to old multiboot feature.

* Thu Oct  9 2003 Harald Hoyer <harald@redhat.de> 2:1.2.1-1
- second round at updating to 1.2.1

* Thu Oct 09 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- first round at updating to 1.2.1

* Sat Sep 27 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- add /boot/tape0 for .tdf tape boots

* Fri Jul 25 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- apply dasdfmt patch from 1.2.1

* Fri Jun 20 2003 Phil Knirsch <pknirsch@redhat.com> 1.1.7-1
- Updated to latest upstream version 1.1.7

* Fri May 02 2003 Pete Zaitcev <zaitcev@redhat.com> 1.1.6-7
- Fix usage of initialized permissions for bootmap.

* Tue Apr 29 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- add extra tape loader from Pete Zaitcev

* Mon Apr 14 2003 Karsten Hopp <karsten@redhat.de> 2:1.1.6-5
- drop cpint support

* Mon Mar 24 2003 Karsten Hopp <karsten@redhat.de> 1.1.6-4
- use multiboot as default
- add option to disable multiboot 

* Sat Mar 22 2003 Karsten Hopp <karsten@redhat.de> 1.1.6-3
- add multiboot patch

* Mon Mar 10 2003 Karsten Hopp <karsten@redhat.de> 1.1.6-2
- added percentage patch (used by anaconda to display progress bars)

* Thu Feb 27 2003 Phil Knirsch <pknirsch@redhat.com> 1.1.6-1
- Updated to newest upstream version 1.1.6

* Tue Feb 04 2003 Phil Knirsch <pknirsch@redhat.com> 1.1.5-1
- Updated to newest upstream version 1.1.5

* Tue Feb 04 2003 Karsten Hopp <karsten@redhat.de> 1.1.4-3
- install libraries in /lib*, not /usr/lib*, they are required
  by some tools in /sbin

* Sun Feb 02 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- fix filelist to not include debug files

* Fri Jan 24 2003 Phil Knirsch <pknirsch@redhat.com> 1.1.4-1
- Updated to latest upstream version of IBM.
- Removed all unecessary patches and updated still needed patches.
- Fixed version number. Needed to introduce epoch though.
- A little specfile cleanup.
- Dropped oco-setver and oco-convert as we don't need them anymore.

* Wed Jan 22 2003 Phil Knirsch <pknirsch@redhat.com> 20020226-4
- Added ExclusiveArch tag.

* Mon Oct 21 2002 Phil Knirsch <pknirsch@redhat.com> 20020226-3
- Removed fdisk -> fdasd symlink. Is now provided by util-linux.
- Disabled f5 patch for s390x for now. Enable it later for newer kernels again.

* Mon May 27 2002 Phil Knirsch <pknirsch@redhat.com>
- Fixed dasdview to build on kernels > 2.4.18.

* Wed Apr 24 2002 Karsten Hopp <karsten@redhat.de>
- add IBM 5 patch

* Tue Jan 29 2002 Karsten Hopp <karsten@redhat.de>
- add IBM 4 patch
- add profile.d scripts to set correct TERM in 3270 console

* Thu Dec 18 2001 Karsten Hopp <karsten@redhat.de>
- add cpint programs

* Mon Nov 26 2001 Harald Hoyer <harald@redhat.de> 20011012-6
- fix for #56720

* Thu Nov 15 2001 Karsten Hopp <karsten@redhat.de>
- add fdisk - > fdasd symlink

* Thu Nov 12 2001 Karsten Hopp <karsten@redhat.de>
- add IBM patch (11/09/2001) and redo percentage patch

* Thu Nov 08 2001 Karsten Hopp <karsten@redhat.de>
- re-enable DASD if dasdfmt is interrupted with Ctrl-C

* Mon Nov 05 2001 Harald Hoyer <harald@redhat.de> 20011012-4
- added s390-tools-dasdfmt-percentage.patch

* Mon Oct 22 2001 Karsten Hopp <karsten@redhat.de>
- remove postinstall script

* Mon Oct 15 2001 Karsten Hopp <karsten@redhat.de>
- add IBM's s390-utils-2.patch
- add console to securetty

* Mon Oct 01 2001 Karsten Hopp <karsten@redhat.de>
- added oco-setkver and oco-convert

* Fri Aug 31 2001 Karsten Hopp <karsten@redhat.de>
- don't write error message in silent mode

* Thu Aug 23 2001 Harald Hoyer <harald@redhat.de>
- added s390-tools-dasdfmt-status.patch

* Tue Aug 21 2001 Karsten Hopp <karsten@redhat.de>
- update to the version from Aug 20

* Tue Aug 14 2001 Karsten Hopp <karsten@redhat.de>
- fix permissions

* Mon Aug 13 2001 Karsten Hopp <karsten@redhat.de>
- rename package to s390utils. s390-tools is no longer needed.

* Thu Aug 02 2001 Karsten Hopp <karsten@redhat.de>
- initial build
