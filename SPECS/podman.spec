%global with_check 0

%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0

%define gobuild(o:) \
GO111MODULE=off go build -buildmode pie -compiler gc -tags="rpm_crashtraceback ${BUILDTAGS:-}" -ldflags "${LDFLAGS:-} -linkmode=external -compressdwarf=false -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n') -extldflags '%__global_ldflags'" -a -v %{?**};

%global import_path github.com/containers/podman
%global branch v4.6.1-rhel
%global commit0 227b84e26d5526dc4f4b3b2dba81610c0db8932c
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global cataver 0.1.7
#%%global dnsnamever 1.3.0
%global commit_dnsname 18822f9a4fb35d1349eb256f4cd2bfd372474d84
%global shortcommit_dnsname %(c=%{commit_dnsname}; echo ${c:0:7})
%global gvproxyrepo gvisor-tap-vsock
%global gvproxyver 0.7.1
%global commit_gvproxy 97028a6a6d6af2f26680f4fdf9dd15323de07804

Epoch: 3
Name: podman
Version: 4.6.1
Release: 8%{?dist}
Summary: Manage Pods, Containers and Container Images
License: Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0
URL: https://%{name}.io/
%if 0%{?branch:1}
Source0: https://%{import_path}/tarball/%{commit0}/%{branch}-%{shortcommit0}.tar.gz
%else
Source0: https://%{import_path}/archive/%{commit0}/%{name}-%{version}-%{shortcommit0}.tar.gz
%endif
Source1: https://github.com/openSUSE/catatonit/archive/v%{cataver}.tar.gz
#Source2: https://github.com/containers/dnsname/archive/v%%{dnsnamever}.tar.gz
Source2: https://github.com/containers/dnsname/archive/%{commit_dnsname}/dnsname-%{shortcommit_dnsname}.tar.gz
Source4: https://github.com/containers/gvisor-tap-vsock/archive/%{commit_gvproxy}/gvisor-tap-vsock-%{commit_gvproxy}.tar.gz
# https://fedoraproject.org/wiki/PackagingDrafts/Go#Go_Language_Architectures
ExclusiveArch: %{go_arches}
Provides: %{name}-manpages = %{epoch}:%{version}-%{release}
Obsoletes: %{name}-manpages < %{epoch}:%{version}-%{release}
BuildRequires: %{_bindir}/envsubst
BuildRequires: golang >= 1.20.6
BuildRequires: glib2-devel
BuildRequires: glibc-devel
BuildRequires: glibc-static
BuildRequires: git-core
BuildRequires: gpgme-devel
BuildRequires: libassuan-devel
BuildRequires: libgpg-error-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: ostree-devel
BuildRequires: pkgconfig
BuildRequires: make
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: shadow-utils-subid-devel
BuildRequires: python3
# for catatonit
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: gcc
BuildRequires: libtool
Requires: containers-common >= 2:1-27
Requires: containernetworking-plugins >= 0.9.1-1
Suggests: netavark
Requires: iptables
Requires: nftables
Obsoletes: oci-systemd-hook < 1
Requires: libseccomp >= 2.5
Requires: conmon >= 2.0.25
Requires: (container-selinux if selinux-policy)
Requires: slirp4netns >= 0.4.0-1
Requires: runc >= 1.0.0-57
Requires: fuse-overlayfs
Requires: %{name}-catatonit >= %{epoch}:%{version}-%{release}
Requires: %{name}-plugins >= %{epoch}:%{version}-%{release}
Requires: oci-runtime
Provides: podmansh = %{epoch}:%{version}-%{release}
Provides: podman-podmansh = %{epoch}:%{version}-%{release}
Provides: podman-shell = %{epoch}:%{version}-%{release}

%description
%{name} (Pod Manager) is a fully featured container engine that is a simple
daemonless tool.  %{name} provides a Docker-CLI comparable command line that
eases the transition from other container engines and allows the management of
pods, containers and images.  Simply put: alias docker=%{name}.
Most %{name} commands can be run as a regular user, without requiring
additional privileges.

%{name} uses Buildah(1) internally to create container images.
Both tools share image (not container) storage, hence each can use or
manipulate images (but not containers) created by the other.

%{summary}
%{name} Simple management tool for pods, containers and images

%package docker
Summary: Emulate Docker CLI using %{name}
BuildArch: noarch
Requires: %{name} = %{epoch}:%{version}-%{release}
Provides: docker = %{epoch}:%{version}-%{release}

%description docker
This package installs a script named docker that emulates the Docker CLI by
executes %{name} commands, it also creates links between all Docker CLI man
pages and %{name}.

%package remote
Summary: A remote CLI for Podman: A Simple management tool for pods, containers and images

%description remote
%{name}-remote provides a local client interacting with a Podman backend
node through a RESTful API tunneled through a ssh connection. In this context,
a %{name} node is a Linux system with Podman installed on it and the API
service activated.

Credentials for this session can be passed in using flags, environment
variables, or in containers.conf.

%package catatonit
Summary: A signal-forwarding process manager for containers
Requires: %{name} = %{epoch}:%{version}-%{release}

%description catatonit
Catatonit is a /sbin/init program for use within containers. It
forwards (almost) all signals to the spawned child, tears down
the container when the spawned child exits, and otherwise
cleans up other exited processes (zombies).

This is a reimplementation of other container init programs (such as
"tini" or "dumb-init"), but uses modern Linux facilities (such as
signalfd(2)) and has no additional features.

%package plugins
Summary: Plugins for %{name}
Requires: dnsmasq
Recommends: %{name}-gvproxy = %{epoch}:%{version}-%{release}

%description plugins
This plugin sets up the use of dnsmasq on a given CNI network so
that Pods can resolve each other by name.  When configured,
the pod and its IP address are added to a network specific hosts file
that dnsmasq will read in.  Similarly, when a pod
is removed from the network, it will remove the entry from the hosts
file.  Each CNI network will have its own dnsmasq instance.

%package tests
Summary: Tests for %{name}
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires: %{name}-plugins = %{epoch}:%{version}-%{release}
#Requires: bats  (which RHEL8 doesn't have. If it ever does, un-comment this)
Requires: nmap-ncat
Requires: httpd-tools
Requires: jq
Requires: socat
Requires: skopeo
Requires: openssl
Requires: buildah
Requires: gnupg
Requires: git-daemon

%description tests
%{summary}

This package contains system tests for %{name}

%package gvproxy
Summary: Go replacement for libslirp and VPNKit

%description gvproxy
A replacement for libslirp and VPNKit, written in pure Go.
It is based on the network stack of gVisor. Compared to libslirp,
gvisor-tap-vsock brings a configurable DNS server and
dynamic port forwarding.

%prep
%if 0%{?branch:1}
%autosetup -Sgit -n containers-%{name}-%{shortcommit0}
%else
%autosetup -Sgit -n %{name}-%{commit0}
%endif
sed -i 's;@@PODMAN@@\;$(BINDIR);@@PODMAN@@\;%{_bindir};' Makefile
sed -i 's,-Werror,,' pkg/rootless/rootless_linux.go
tar fx %{SOURCE1}
pushd catatonit-%{cataver}
sed -i '$d' configure.ac
popd
tar fx %{SOURCE2}
tar fx %{SOURCE4}

# this is shipped by skopeo: containers-common subpackage
rm -rf docs/source/markdown/containers-mounts.conf.5.md

%build
# build catatonit first because C code
pushd catatonit-%{cataver}
autoreconf -fi
%configure
CFLAGS="%{optflags} -fPIE -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
%{__make} %{?_smp_mflags}
# Make sure we *always* build a static binary for catatonit. Otherwise we'll break containers
# that don't have the necessary shared libs.
set +e
/usr/bin/ldd catatonit
if [ $? != 1 ]; then
   echo "ERROR: catatonit binary must be statically linked!"
   exit 1
fi
set -e
popd

export GO111MODULE=on
export GOPATH=$(pwd)/_build:$(pwd)
CGO_CFLAGS="%{optflags} -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
# These extra flags present in $CFLAGS have been skipped for now as they break the build
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-flto=auto//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-Wp,D_GLIBCXX_ASSERTIONS//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-specs=\/usr\/lib\/rpm\/redhat\/redhat-annobin-cc1//g')

%ifarch x86_64
export CGO_CFLAGS+=" -m64 -mtune=generic -fcf-protection=full"
%endif

mkdir _build
pushd _build
mkdir -p src/github.com/containers
ln -s ../../../../ src/github.com/containers/podman
popd
ln -s vendor src

rm -rf vendor/github.com/containers/storage/drivers/register/register_btrfs.go

unset LDFLAGS
# build date. FIXME: Makefile uses '/v2/libpod', that doesn't work here?
LDFLAGS="-X %{import_path}/libpod/define.buildInfo=$(date +%s)"

# build rootlessport
%gobuild -o bin/rootlessport %{import_path}/cmd/rootlessport

export BUILDTAGS="seccomp btrfs_noversion exclude_graphdriver_devicemapper exclude_graphdriver_btrfs $(hack/libdm_tag.sh) $(hack/selinux_tag.sh) $(hack/systemd_tag.sh) $(hack/libsubid_tag.sh)"
%gobuild -o bin/%{name} %{import_path}/cmd/%{name}

# build %%{name}-remote
export BUILDTAGS="remote $BUILDTAGS"
%gobuild -o bin/%{name}-remote %{import_path}/cmd/%{name}

# build quadlet
%gobuild -o bin/quadlet %{import_path}/cmd/quadlet

%{__make} docs
%{__make} docker-docs

# build dnsname plugin
unset LDFLAGS
pushd dnsname-%{commit_dnsname}
mkdir _build
pushd _build
mkdir -p src/github.com/containers
ln -s ../../../../ src/github.com/containers/dnsname
popd
ln -s vendor src
export GOPATH=$(pwd)/_build:$(pwd)
%gobuild -o bin/dnsname github.com/containers/dnsname/plugins/meta/dnsname
popd

pushd gvisor-tap-vsock-%{commit_gvproxy}
mkdir _build
pushd _build
mkdir -p src/github.com/containers
ln -s ../../../../ src/github.com/containers/gvisor-tap-vsock
popd
ln -s vendor src
export GOPATH=$(pwd)/_build:$(pwd)
%gobuild -o bin/gvproxy github.com/containers/gvisor-tap-vsock/cmd/gvproxy
popd

%install
PODMAN_VERSION=%{version} %{__make} PREFIX=%{buildroot}%{_prefix} ETCDIR=%{buildroot}%{_sysconfdir} \
        install.bin \
        install.remote \
        install.man \
        install.systemd \
        install.completions \
        install.docker \
        install.docker-docs

sed -i 's;%{buildroot};;g' %{buildroot}%{_bindir}/docker

# remove unwanted man pages
rm -f %{buildroot}%{_mandir}/man5/docker*.5

# install test scripts, but not the internal helpers.t meta-test
ln -s ./ ./vendor/src # ./vendor/src -> ./vendor
install -d -p %{buildroot}/%{_datadir}/%{name}/test/system
cp -pav test/system %{buildroot}/%{_datadir}/%{name}/test/
rm -f               %{buildroot}/%{_datadir}/%{name}/test/system/*.t

# do not include docker and podman-remote man pages in main package
for file in `find %{buildroot}%{_mandir}/man[15] -type f | sed "s,%{buildroot},," | grep -v -e remote -e docker`; do
    echo "$file*" >> podman.file-list
done

# install catatonit
install -dp %{buildroot}%{_libexecdir}/catatonit
install -p catatonit-%{cataver}/catatonit %{buildroot}%{_libexecdir}/catatonit
install -dp %{buildroot}%{_libexecdir}/podman
install -dp %{buildroot}%{_datadir}/licenses/podman-catatonit
install -p catatonit-%{cataver}/COPYING %{buildroot}%{_datadir}/licenses/podman-catatonit/COPYING
ln -s %{_libexecdir}/catatonit/catatonit %{buildroot}%{_libexecdir}/podman/catatonit

# install dnsname plugin
pushd dnsname-%{commit_dnsname}
%{__make} PREFIX=%{_prefix} DESTDIR=%{buildroot} install
popd

# install gvproxy
pushd gvisor-tap-vsock-%{commit_gvproxy}
install -dp %{buildroot}%{_libexecdir}/%{name}
install -p -m0755 bin/gvproxy %{buildroot}%{_libexecdir}/%{name}
popd

%check
%if 0%{?with_check}
# Since we aren't packaging up the vendor directory we need to link
# back to it somehow. Hack it up so that we can add the vendor
# directory from BUILD dir as a gopath to be searched when executing
# tests from the BUILDROOT dir.
ln -s ./ ./vendor/src # ./vendor/src -> ./vendor

export GOPATH=%{buildroot}/%{gopath}:$(pwd)/vendor:%{gopath}

%if ! 0%{?gotest:1}
%global gotest go test
%endif

%gotest %{import_path}/cmd/%{name}
%gotest %{import_path}/libkpod
%gotest %{import_path}/libpod
%gotest %{import_path}/pkg/registrar
%endif

%triggerpostun -- %{name} < 1.1
%{_bindir}/%{name} system renumber
exit 0

%preun
if [ $1 == 0 ]; then
  systemctl stop podman.service > /dev/null 2>&1 || :
  systemctl stop podman.socket > /dev/null 2>&1 || :
  systemctl disable podman.service > /dev/null 2>&1 || :
  systemctl disable podman.socket > /dev/null 2>&1 || :
fi
:

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files -f podman.file-list
%license LICENSE
%doc README.md CONTRIBUTING.md install.md transfer.md
%{_bindir}/%{name}
%{_bindir}/%{name}sh
%{_libexecdir}/%{name}/quadlet
%{_libexecdir}/%{name}/rootlessport
%{_datadir}/bash-completion/completions/%{name}
# By "owning" the site-functions dir, we don't need to Require zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_%{name}
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%ghost %dir %{_sysconfdir}/cni/net.d
%ghost %{_sysconfdir}/cni/net.d/87-%{name}-bridge.conflist
%{_unitdir}/*.service
%{_unitdir}/*.socket
%{_unitdir}/*.timer
%{_userunitdir}/*.service
%{_userunitdir}/*.socket
%{_userunitdir}/*.timer
%{_usr}/lib/tmpfiles.d/%{name}.conf

%files docker
%{_bindir}/docker
%{_mandir}/man1/docker*.1*
%{_tmpfilesdir}/%{name}-docker.conf
/usr/share/user-tmpfiles.d/%{name}-docker.conf

%files remote
%license LICENSE
%{_bindir}/%{name}-remote
%{_mandir}/man1/%{name}-remote*.*
%{_datadir}/bash-completion/completions/%{name}-remote
%dir %{_datadir}/fish
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/%{name}-remote.fish
%dir %{_datadir}/zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_%{name}-remote

%files catatonit
%license COPYING
%doc README.md
%dir %{_libexecdir}/catatonit
%{_libexecdir}/catatonit/catatonit
%dir %{_libexecdir}/podman
%{_libexecdir}/podman/catatonit
%{_usr}/lib/systemd/system-generators/podman-system-generator
%{_usr}/lib/systemd/user-generators/podman-user-generator

%files plugins
%license dnsname-%{commit_dnsname}/LICENSE
%doc dnsname-%{commit_dnsname}/{README.md,README_PODMAN.md}
%{_libexecdir}/cni/dnsname

%files tests
%license LICENSE
%{_datadir}/%{name}/test

%files gvproxy
%license gvisor-tap-vsock-%{commit_gvproxy}/LICENSE
%doc gvisor-tap-vsock-%{commit_gvproxy}/README.md
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/gvproxy

%changelog
* Tue Jan 23 2024 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-8
- Make the module buildable again
- Resolves: RHEL-16299

* Fri Jan 19 2024 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-7
- update to the latest content of https://github.com/containers/podman/tree/v4.6.1-rhel
  (https://github.com/containers/podman/commit/227b84e)
- Resolves: RHEL-20910

* Thu Jan 18 2024 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-6
- Update gvproxy to be rebuildable with newer versions of golang
- Related: RHEL-19138

* Mon Dec 04 2023 Lokesh Mandvekar <lsm5@redhat.com> - 3:4.6.1-5
- Rebuild with golang 1.20.10 for CVE-2023-39321
- Related: Jira:RHEL-4515

* Fri Aug 25 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-4
- update to the latest content of https://github.com/containers/podman/tree/v4.6.1-rhel
  (https://github.com/containers/podman/commit/ea33dce)
- Related: #2176055

* Tue Aug 22 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-3
- add podmansh provides
- Related: #2176055

* Wed Aug 16 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-2
- update to the latest content of https://github.com/containers/podman/tree/v4.6.1-rhel
  (https://github.com/containers/podman/commit/1b2fadd)
- Resolves: #2232127

* Fri Aug 11 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.1-1
- update to https://github.com/containers/podman/releases/tag/v4.6.1
- Related: #2176055

* Fri Aug 04 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-3
- build podman 4.6.0 off main branch for early testing of zstd compression
- Related: #2176055

* Fri Aug 04 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-2
- update license token to be SPDX compatible
- Related: #2176055

* Fri Jul 21 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-1
- update to latest content of https://github.com/containers/podman/releases/tag/4.6.0
  (https://github.com/containers/podman/commit/38e6fab9664c6e59b66e73523b307a56130316ae)

* Fri Jul 14 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-0.3
- update to 4.6.0-rc2
- Related: #2176055

* Tue Jul 11 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-0.2
- add missing Requires on podman-plugins
- Resolves: #2220931

* Mon Jul 10 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.6.0-0.1
- update to 4.6.0-rc1
- Related: #2176055

* Thu Jun 15 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.5.1-5
- rebuild for following CVEs:
CVE-2022-41724 CVE-2022-41725 CVE-2023-24537 CVE-2023-24538 CVE-2023-24534 CVE-2023-24536 CVE-2022-41723 CVE-2023-24539 CVE-2023-24540 CVE-2023-29400
- Resolves: #2179945
- Resolves: #2187315
- Resolves: #2187361
- Resolves: #2203678
- Resolves: #2207507

* Wed Jun 14 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.5.1-4
- rebuild for following CVEs:
CVE-2023-25173 CVE-2022-41724 CVE-2022-41725 CVE-2023-24537 CVE-2023-24538 CVE-2023-24534 CVE-2023-24536 CVE-2022-41723 CVE-2023-24539 CVE-2023-24540 CVE-2023-29400
- Resolves: #2175071
- Resolves: #2179950
- Resolves: #2187318
- Resolves: #2187366
- Resolves: #2203681
- Resolves: #2207512

* Wed Jun 14 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.5.1-3
- update to https://github.com/containers/gvisor-tap-vsock/releases/tag/v0.6.1
- Related: #2176055

* Tue Jun 06 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.5.1-2
- add missing BuildRequires
- Related: #2176055

* Tue Jun 06 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.5.1-1
- update to https://github.com/containers/podman/releases/tag/v4.5.1
- Related: #2176055

* Tue Jun 06 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-19
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/bcea446)
- Related: #2176055

* Tue May 16 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-18
- _user_tmpfilesdir definition is not part of systemd in 8.9
- Related: #2176055

* Tue May 16 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-17
- add missing BR: systemd-rpm-macros
- Related: #2176055

* Fri May 12 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-16
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/8b741dc)
- Related: #2176055

* Tue Apr 18 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-15
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/fd0ea3b)
- Related: #2176055

* Tue Apr 18 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-14
- build and add missing docker man pages
- Related: #2176055

* Mon Apr 03 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-13
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/05037d3)
- Related: #2176055

* Thu Mar 30 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-12
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/67f7e1e)
- Resolves: #2182052

* Fri Mar 24 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-11
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/4461c9c)
- Related: #2176055

* Tue Mar 21 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-10
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/bf400bd)
- Resolves: #2179449

* Fri Mar 17 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-9
- update to the latest content of https://github.com/containers/podman/tree/v4.4.1-rhel
  (https://github.com/containers/podman/commit/ffc2614)
- Related: #2176055

* Wed Mar 08 2023 Jindrich Novy <jnovy@redhat.com> - 3:4.4.1-8
- use ldd directly to check for static link - avoid broken file utility
- Related: #2176055

* Thu Dec 15 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.3.1-2
- update to the latest content of https://github.com/containers/podman/tree/v4.3.1-rhel
  (https://github.com/containers/podman/commit/d9a6336)
- Resolves: #2144754

* Mon Nov 14 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.3.1-1
- update to https://github.com/containers/podman/releases/tag/v4.3.1
- Related: #2123641

* Mon Nov 07 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.3.0-2
- fix build
- Resolves: #2124430

* Wed Nov 02 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.3.0-1
- update to https://github.com/containers/podman/releases/tag/v4.3.0
- Related: #2123641

* Mon Oct 31 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.2.0-3
- update to the latest content of https://github.com/containers/podman/tree/v4.2.0-rhel
  (https://github.com/containers/podman/commit/35c0df3)
- Related: #2123641

* Fri Oct 21 2022 Jindrich Novy <jnovy@redhat.com> - 3:4.2.0-2
- update to the latest content of https://github.com/containers/podman/tree/v4.2.0-rhel
  (https://github.com/containers/podman/commit/d520a5c)
- Related: #2123641

* Mon Oct 17 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.0-1
- update to the latest content of https://github.com/containers/podman/tree/v4.2.0-rhel
  (https://github.com/containers/podman/commit/4978898)
- Related: #2123641

* Wed Sep 28 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.1-3
- switch to upstream maintenance branch
- Resolves: #2126697
- Resolves: #2097708

* Thu Sep 15 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.1-2
- fix source tarball list
- Related: #2123641

* Thu Sep 08 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.1-1
- update to https://github.com/containers/podman/releases/tag/v4.2.1
- Related: #2123641

* Thu Aug 11 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.0-1
- update to https://github.com/containers/podman/releases/tag/v4.2.0
  (https://github.com/containers/podman/commit/7fe5a419cfd2880df2028ad3d7fd9378a88a04f4)
- Related: #2061390

* Fri Aug 05 2022 Lokesh Mandvekar <lsm5@redhat.com> - 2:4.2.0-0.2rc3
- update to 4.2.0-rc3
- Related: #2061390

* Mon Aug 01 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.2.0-0.1rc2
- update to 4.2.0-rc2
- Related: #2061390

* Fri Jul 08 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-6
- update to the latest content of https://github.com/containers/podman/tree/v4.1.1-rhel
  (https://github.com/containers/podman/commit/fa692a6)
- Related: #2061390

* Fri Jul 01 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-5
- don't allow systemd commands to fail the transaction
- Related: #2061390

* Thu Jun 30 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-4
- stopping service/socket might execute podman command too - move to preun
- Related: #2061390

* Thu Jun 30 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-3
- be sure podman socket is stopped only in case of package removal
- Related: #2061390

* Thu Jun 30 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-2
- be sure podman socket is closed after podman package is removed
- Related: #2061390

* Wed Jun 15 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.1-1
- update to https://github.com/containers/podman/releases/tag/v4.1.1
- Related: #2061390

* Wed May 18 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.0-3
- Require CNI and make netavark optional
- Related: #2061390

* Wed May 11 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.0-2
- update gvisor-tap-vsock to 0.2.0 to fix compilation with golang 1.18
- Related: #2061390

* Mon May 09 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.1.0-1
- update to https://github.com/containers/podman/releases/tag/v4.1.0
- Related: #2061390

* Fri Apr 08 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.3-2
- Related: #2061390

* Fri Apr 01 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.3-1
- update to https://github.com/containers/podman/releases/tag/v4.0.3
- Related: #2061390

* Fri Mar 18 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.2-2
- bump minimal libseccomp version requirement
- Related: #2061390

* Mon Mar 07 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.2-1
- update to https://github.com/containers/podman/releases/tag/v4.0.2
- Related: #2061390

* Mon Feb 28 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.1-1
- update to https://github.com/containers/podman/releases/tag/v4.0.1
- Related: #2001445

* Mon Feb 21 2022 Lokesh Mandvekar <lsm5@redhat.com> - 2:4.0.0-3
- use correct commit 49f8da72 for podman, previous commit said 4.0.1-dev
- Related: #2001445

* Mon Feb 21 2022 Lokesh Mandvekar <lsm5@redhat.com> - 2:4.0.0-2
- install podman-plugins for gating tests
- Related: #2001445

* Fri Feb 18 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-1
- update to podman-4.0.0 final
- Related: #2001445

* Thu Feb 17 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.31
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/a34f279)
- Related: #2001445

* Wed Feb 16 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.30
- fix linker flags to assure -D_FORTIFY_SOURCE=2 is present at the command line
- Related: #2001445

* Tue Feb 15 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.29
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/ab3e566)
- Related: #2001445

* Mon Feb 14 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.28
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/b0a445e)
- Related: #2001445

* Fri Feb 11 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.27
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/c4a9aa7)
- Related: #2001445

* Thu Feb 10 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.26
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/5b2d96f)
- Related: #2001445

* Wed Feb 09 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.25
- set CGO_CFLAGS explicitly
- Related: #2001445

* Mon Feb 07 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.24
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/2dca7b2)
- Related: #2001445

* Fri Feb 04 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.23
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/4ad9e00)
- Related: #2001445

* Fri Feb 04 2022 Jindrich Novy <jnovy@redhat.com> - 2:4.0.0-0.22
- update to the latest content of https://github.com/containers/podman/tree/v4.0
  (https://github.com/containers/podman/commit/337f706)
- Related: #2001445

* Thu Jan 27 2022 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.7
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/a54320a)
- Related: #2001445

* Thu Jan 20 2022 Jindrich Novy <jnovy@redhat.com> - 2:3.4.5-0.6
- update gating tests
- Related: #2001445

* Mon Jan 17 2022 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.5
- add git-daemon to test subpackage
  (https://github.com/containers/podman/issues/12851)
- Related: #2001445

* Fri Jan 14 2022 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.4
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/63134a1)
- Related: #2001445

* Tue Jan 11 2022 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.3
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/3f57b6e)
- Related: #2001445

* Fri Dec 17 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.2
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/17788ed)
- Related: #2001445

* Thu Dec 09 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.5-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/b8fde5c)
- Related: #2001445

* Wed Dec 08 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.4-0.2
- drop patch applied upstream
- Related: #2001445

* Wed Dec 08 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.4-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/49f589d)
- Related: #2001445

* Mon Dec 06 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.9
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/fe44757)
- Related: #2001445

* Thu Dec 02 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.8
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/815f36a)
- Related: #2001445

* Wed Dec 01 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.7
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/31bc358)
- Related: #2001445

* Tue Nov 23 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.6
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/e3a7a74)
- add libsubid_tag.sh into BUILDTAGS
- Related: #2001445

* Mon Nov 22 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.5
- do not put patch URL as the backported patch will get overwritten when
  "spectool -g -f" is executed
- Related: #2001445

* Mon Nov 22 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.4
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/7203178)
- Related: #2001445

* Tue Nov 16 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.3
- remove -t 0 from podman gating test
- Related: #2001445

* Mon Nov 15 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.2
- add BuildRequires: shadow-utils-subid-devel
- Related: #2001445

* Mon Nov 15 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.3-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/4808a63)
- Related: #2001445

* Fri Nov 12 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.2-0.4
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/fd010ad)
- Related: #2001445

* Tue Nov 09 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.2-0.3
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/8de9950)
- Related: #2001445

* Tue Nov 02 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.2-0.2
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/75023e9)
- Related: #2001445

* Thu Oct 21 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.2-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/09aade7)
- Related: #2001445

* Tue Oct 19 2021 Jindrich Novy <jnovy@redhat.com>
- more dependency tightening - thanks to Michael Rochefort for noticing
- Related: #2001445

* Mon Oct 18 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.1-3
- fix also dependency for podman-catatonit
- Related: #2001445

* Mon Oct 18 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.1-2
- respect Epoch in subpackage dependencies
- Related: #2001445

* Fri Oct 15 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.1-0.3
- fix Release to denote this is not a development version
- Related: #2001445

* Fri Oct 15 2021 Jindrich Novy <jnovy@redhat.com> - 1:3.4.1-0.2
- bump Epoch to preserve upgrade path
- Related: #2001445

* Wed Oct 13 2021 Jindrich Novy <jnovy@redhat.com> - 3.4.1-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.4
  (https://github.com/containers/podman/commit/c15c154)
- Related: #2001445

* Wed Oct 13 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.21
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/72e87c0)
- Related: #2001445

* Mon Oct 11 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.20
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/ea86893)
- Related: #2001445

* Fri Oct 08 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.19
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/14c0fcc)
- Related: #2001445

* Thu Oct 07 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.18
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/bfb904b)
- Related: #2001445

* Wed Oct 06 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.17
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/8bcc086)
- Related: #2001445

* Tue Oct 05 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.16
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/c963a50)
- Related: #2001445

* Mon Oct 04 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.15
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/b9d8c63)
- Related: #2001445

* Fri Oct 01 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.14
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/317e20a)
- Related: #2001445

* Thu Sep 30 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.13
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/b187dfe)
- Related: #2001445

* Wed Sep 29 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.12
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/cd10304)
- Related: #2001445

* Mon Sep 27 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.11
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/b60cff8)
- Related: #2001445

* Fri Sep 24 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.10
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/800d594)
- Related: #2001445

* Thu Sep 23 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.9
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/1dba601)
- Related: #2001445

* Wed Sep 22 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.8
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/8e2d25e)
- Related: #2001445

* Tue Sep 21 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.7
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/b925d70)
- Related: #2001445

* Mon Sep 20 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.6
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/ddb3844)
- Related: #2001445

* Fri Sep 17 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/84c61b7)
- Related: #2001445

* Thu Sep 16 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/5f41ffd)
- update to https://github.com/containers/podman-machine-cni/releases/tag/v0.2.0
- Related: #2001445

* Wed Sep 15 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/323fe36)
- Related: #2001445

* Mon Sep 13 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/0f3d3bd)
- Related: #2001445

* Fri Sep 10 2021 Jindrich Novy <jnovy@redhat.com> - 4.0.0-0.1
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/63f6656)
- Related: #2001445

* Mon Aug 30 2021 Lokesh Mandvekar <lsm5@fedoraproject.org> - 3.3.1-7
- update to the latest content of https://github.com/containers/podman/tree/v3.3.1-rhel
  (https://github.com/containers/podman/commit/405507a)
- Related: #1934415
- correct previous changelog entry

* Mon Aug 30 2021 Lokesh Mandvekar <lsm5@redhat.com> - 3.3.1-6
- update to the latest content of https://github.com/containers/podman/tree/v3.3.1-rhel
  (https://github.com/containers/podman/commit/405507a)
- Related: #1934415

* Mon Aug 30 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.1-5
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/7752c73)
- Related: #1934415

* Fri Aug 27 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.1-4
- podman-gvproxy -> gvproxy
- Related: #1934415

* Thu Aug 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.1-3
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/d09259a)
- Related: #1934415

* Wed Aug 25 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.1-2
- amend containers-common dependency
- Related: #1934415

* Wed Aug 25 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.1-1
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/8809aed)
- Related: #1934415

* Tue Aug 17 2021 Lokesh Mandvekar <lsm5@redhat.com> - 3.3.0-8
- Bump podman to v3.3.0
- Related: #1966538

* Tue Aug 17 2021 Lokesh Mandvekar <lsm5@redhat.com> - 3.3.0-7
- podman-plugins Recommends: podman-gvproxy
- Related: #1934415

* Tue Aug 17 2021 Lokesh Mandvekar <lsm5@redhat.com> - 3.3.0-6
- update podman to v3.3.0-rc3
- update dnsname to v1.3.0
- add podman-machine-cni commit afab2d8
- add gvproxy v0.1.0
- Related: #1934415

* Tue Aug 17 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-5
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/39cab79)
- Related: #1934415

* Thu Aug 12 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-4
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/63269b6)
- Related: #1934415

* Wed Aug 11 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-3
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/922699f)
- Related: #1934415

* Thu Aug 05 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-2
- update to the latest content of https://github.com/containers/podman/tree/v3.3
  (https://github.com/containers/podman/commit/57422d2)
- Related: #1934415

* Tue Aug 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-1
- update to 3.3.0 release and switch to the v3.3 maint branch
- Related: #1934415

* Mon Aug 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.22
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/03afc91)
- Related: #1934415

* Fri Jul 30 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.21
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/4429c7c)
- Related: #1934415

* Fri Jul 30 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.20
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/f17b810)
- Related: #1934415

* Thu Jul 29 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.19
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/2041731)
- Related: #1934415

* Thu Jul 29 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.18
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/f9395dd)
- Related: #1934415

* Wed Jul 28 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.17
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/a5de831)
- Related: #1934415

* Tue Jul 27 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.16
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/4f5b19c)
- Related: #1934415

* Mon Jul 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.15
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/ec5c7c1)
- Related: #1934415

* Wed Jul 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.14
- update to the latest content of https://github.com/containers/podman/tree/main
  (https://github.com/containers/podman/commit/0ef01c8)
- Related: #1934415

* Wed Jul 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.13
- switch to the main branch as podman-3.3.x is targeted at 8.5.0
- Related: #1934415

* Wed Jul 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.9
- switch to v3.2.3-rhel branch
- Related: #1934415

* Wed Jul 14 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.8
- update to the latest content of https://github.com/containers/podman/tree/v3.2
  (https://github.com/containers/podman/commit/4136f8b)
- Related: #1934415

* Fri Jul 09 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.7
- update to the latest content of https://github.com/containers/podman/tree/v3.2
  (https://github.com/containers/podman/commit/60d12f7)
- Related: #1934415

* Thu Jul 08 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.6
- update to the latest content of https://github.com/containers/podman/tree/v3.2
  (https://github.com/containers/podman/commit/275b0d8)
- Related: #1934415

* Wed Jul 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.5
- put 87-podman-bridge.conflist to main podman package not podman-remote
- Related: #1934415

* Wed Jul 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.4
- install CNI manually as install.cni target is missing from the Makefile
- simplify unit file packaging
- Related: #1934415

* Mon Jul 05 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.3
- update to the latest content of https://github.com/containers/podman/tree/v3.2
  (https://github.com/containers/podman/commit/6f0bf16)
- Related: #1934415

* Fri Jul 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.2
- install CNI properly
- Related: #1934415

* Fri Jul 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.3-0.1
- update to the latest content of https://github.com/containers/podman/tree/v3.2
  (https://github.com/containers/podman/commit/ac740c6)
- Related: #1934415

* Thu Jul 01 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.2-2
- remove missing unit files
- Related: #1934415

* Thu Jul 01 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.2-1
- consume content from v3.2 upstream branch
- Related: #1934415

* Tue Jun 29 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.12
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/c260cbd)
- Related: #1934415

* Mon Jun 28 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.11
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/0a0ade3)
- Related: #1934415

* Fri Jun 25 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.10
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/d1f57a0)
- Related: #1934415

* Thu Jun 24 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.9
- add missing unit files
- Related: #1934415

* Wed Jun 23 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.8
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e159eb8)
- Related: #1934415

* Tue Jun 22 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.7
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/be15e69)
- Related: #1934415

* Mon Jun 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.6
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/928687e)
- Related: #1934415

* Thu Jun 17 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/814a8b6)
- Related: #1934415

* Tue Jun 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e2f51ee)
- Related: #1934415

* Thu Jun 10 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/d116beb)
- Related: #1934415

* Wed Jun 09 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/da1bade)
- Related: #1934415

* Tue Jun 08 2021 Jindrich Novy <jnovy@redhat.com> - 3.3.0-0.1
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/df3b6da)
- Related: #1934415

* Mon Jun 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.33
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5a209b3)
- Related: #1934415

* Fri Jun 04 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.32
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/f7233a2)
- Related: #1934415

* Thu Jun 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.31
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/52dae69)
- Related: #1934415

* Wed Jun 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.30
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/41c76d6)
- Related: #1934415

* Tue Jun 01 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.29
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/8f5f0cf)
- Related: #1934415

* Mon May 31 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.28
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5923676)
- Related: #1934415

* Thu May 27 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.27
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/d9eb126)
- Related: #1934415

* Wed May 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.26
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/ac94be3)
- Related: #1934415

* Wed May 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.25
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/c5b3cba)
- Related: #1934415

* Tue May 25 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.24
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/a6f0ac2)
- Related: #1934415

* Mon May 24 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.23
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/b060a77)
- Related: #1934415

* Sat May 22 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.22
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/490915c)
- Related: #1934415

* Fri May 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.21
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e48aa8c)
- Related: #1934415

* Thu May 20 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.20
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/8bc39f4)
- Related: #1934415

* Wed May 19 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.19
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/4c75626)
- Related: #1934415

* Wed May 19 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.18
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/959d6a0)
- Related: #1934415

* Mon May 17 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.17
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/3bdbe3c)
- Related: #1934415

* Thu May 13 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.16
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/4dc52f6)
- Related: #1934415

* Wed May 12 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.15
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/59dd357)
- Related: #1934415

* Tue May 11 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.14
- require at least conmon >= 2.0.25 to assure rootless podman is able to start containers
- Related: #1934415

* Tue May 11 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.13
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/8dcd5b8)
- Related: #1934415

* Tue May 11 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.12
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/57b6425)
- Related: #1934415

* Mon May 10 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.11
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/54bed10)
- Related: #1934415

* Fri May 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.10
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/034470e)
- Related: #1934415

* Thu May 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.9
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/b6405c1)
- Related: #1934415

* Thu May 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.8
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/ed6f399)
- Related: #1934415

* Wed May 05 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.7
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/8eefca5)
- Related: #1934415

* Tue May 04 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.6
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/9788289)
- Related: #1934415

* Mon May 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/697ec8f)
- Related: #1934415

* Fri Apr 30 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/49eb047)
- Related: #1934415

* Thu Apr 29 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/db67fed)
- Related: #1934415

* Wed Apr 28 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5dc9faf)
- Related: #1934415

* Mon Apr 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.1
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/9ca53cf)
- Related: #1934415

* Wed Apr 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-11
- use tarball from 3.0.1-rhel branch
- Related: #1934415

* Wed Apr 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-2
- bump release to ensure upgrade path
- Related: #1934415

* Tue Apr 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-1
- revert to 3.0.1-rhel as 3.1.0 and 3.2.0 is currently broken
- Related: #1934415

* Tue Apr 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/2b13c5d)
- Related: #1934415

* Thu Apr 01 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/12881ab)
- Related: #1934415

* Wed Mar 31 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/a373e2f)
- Related: #1934415

* Tue Mar 30 2021 Jindrich Novy <jnovy@redhat.com> - 3.2.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5eb5950)
- Related: #1934415

* Mon Mar 29 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.15
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/ccbe7e9)
- Related: #1934415

* Fri Mar 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.14
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/9e23e0b)
- Related: #1934415

* Thu Mar 25 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.13
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e523d09)
- Related: #1934415

* Wed Mar 24 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.12
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/860de13)
- Related: #1934415

* Tue Mar 23 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.11
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/60c90c3)
- Related: #1934415

* Mon Mar 22 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.10
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/ebc9871)
- Related: #1934415

* Fri Mar 19 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.9
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5d9b070)
- Related: #1934415

* Thu Mar 18 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.8
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/6f6cc1c)
- Related: #1934415

* Wed Mar 17 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.7
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/604459b)
- Related: #1934415

* Tue Mar 16 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.6
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e7dc592)
- Related: #1934415

* Mon Mar 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/fc02d16)
- Related: #1934415

* Fri Mar 12 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/81737b3)
- Related: #1934415

* Thu Mar 11 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e2d35e5)
- Related: #1934415

* Wed Mar 10 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/09473d4)
- Related: #1934415

* Tue Mar 09 2021 Jindrich Novy <jnovy@redhat.com> - 3.1.0-0.1
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/789d579)
- Related: #1934415

* Mon Mar 08 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-6
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/b7c00f2)
- Related: #1934415

* Thu Mar 04 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/87e2056)
- Related: #1934415

* Wed Mar 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-4
- remove docker man page as it was removed upstream
- Related: #1934415

* Wed Mar 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/0a40c5a)
- Related: #1934415

* Mon Feb 22 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/9a2fc37)
- Related: #1883490

* Fri Feb 19 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.1-1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/7e286bc)
- Related: #1883490

* Mon Feb 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/797f1ea)
- Related: #1883490

* Fri Feb 12 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/ddd8a17)
- Related: #1883490

* Wed Feb 10 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.41rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/2b89fe7)
- Related: #1883490

* Tue Feb 09 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.40rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/a5ab59e)
- Related: #1883490

* Sat Feb 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.39rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/288fb68)
- Resolves: #1883490

* Thu Feb 04 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.38rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/82081e8)
- Related: #1883490

* Wed Feb 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.37rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/c2a298e)
- Related: #1883490

* Wed Feb 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.36rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/013770e)
- Related: #1883490

* Wed Feb 03 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.35rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/978c005)
- Related: #1883490

* Tue Feb 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.34rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/67d48c5)
- add Requires: oci-runtime
- Related: #1883490

* Sun Jan 31 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.33rc2
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/745fa4a)
- Related: #1883490

* Wed Jan 27 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.32rc1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/4dbb58d)
- Related: #1883490

* Tue Jan 26 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.31rc1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/dc2f4c6)
- Related: #1883490

* Fri Jan 22 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.30rc1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/469c203)
- Related: #1883490

* Thu Jan 21 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.29rc1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/4ecd2be)
- Related: #1883490

* Tue Jan 19 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.28rc1
- update to the latest content of https://github.com/containers/podman/tree/v3.0
  (https://github.com/containers/podman/commit/ade8a92)
- Related: #1883490

* Mon Jan 18 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.27rc1
- switch from master to release candidate (3.0.0-rc1)
- Related: #1883490

* Mon Jan 18 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.26
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5b3c7a5)
- Related: #1883490

* Fri Jan 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.25
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/83ed464)
- Related: #1883490

* Fri Jan 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.24
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5a166b2)
- Related: #1883490

* Fri Jan 15 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.23
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/3fcf346)
- Related: #1883490

* Thu Jan 14 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.22
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/b2ac2a3)
- Related: #1883490

* Wed Jan 13 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.21
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/f52a9ee)
- require socat for gating tests
- Related: #1914884

* Tue Jan 12 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.20
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5681907)
- Related: #1883490

* Fri Jan 08 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.19
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/78cda71)
- Related: #1883490

* Thu Jan 07 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.18
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/355e387)
- Related: #1883490

* Wed Jan 06 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.17
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/ffe2b1e)
- Related: #1883490

* Tue Jan 05 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.16
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/618c355)
- Related: #1883490

* Mon Jan 04 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.15
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/142b4ac)
- Related: #1883490

* Sat Jan 02 2021 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.14
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/39b1cb4)
- Related: #1883490

* Sat Dec 26 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.13
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/9c9f02a)
- Related: #1883490

* Mon Dec 21 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.12
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/5c6b5ef)
- Related: #1883490

* Tue Dec 15 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.11
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/999d40d)
- Related: #1883490

* Mon Dec 14 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.10
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/a226e6e)
- Related: #1883490

* Fri Dec 11 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.9
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/6823a5d)
- Related: #1883490

* Thu Dec 10 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.8
- update to https://github.com/containers/dnsname/releases/tag/v1.1.1
- Related: #1883490

* Thu Dec 10 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.7
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/9216be2)
- Related: #1883490

* Wed Dec 09 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.6
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/dd295f2)
- Related: #1883490

* Tue Dec 08 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.5
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/e2f9120)
- Related: #1883490

* Mon Dec 07 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.4
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/035d289)
- Related: #1883490

* Sat Dec 05 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.3
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/8e83799)
- Related: #1883490

* Fri Dec 04 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.2
- update to the latest content of https://github.com/containers/podman/tree/master
  (https://github.com/containers/podman/commit/70284b1)
- Related: #1883490

* Thu Dec 03 2020 Jindrich Novy <jnovy@redhat.com> - 3.0.0-0.1
- attempt to fix gating tests with patch from Matt Heon
- Related: #1883490

* Tue Dec 01 2020 Jindrich Novy <jnovy@redhat.com> - 2.2.0-1
- update to https://github.com/containers/podman/releases/tag/v2.2.0
- Related: #1883490

* Thu Nov 05 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-8
- fix branch name setup
- Related: #1883490

* Thu Nov 05 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-7
- attempt to fix linker error with golang-1.15
- add Requires: httpd-tools to tests, needed to work around
  missing htpasswd in docker registry image, thanks to Ed Santiago
- Related: #1883490

* Fri Oct 23 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-6
- add tests/roles subdirectory
- Related: #1883490

* Fri Oct 23 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-5
- use shortcommit ID in branch tarball name
- Related: #1883490

* Thu Oct 22 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-4
- use the correct upstream tarball
- Related: #1883490

* Thu Oct 22 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-3
- do not lock down to upstream branch for 8.4.0 yet and consume
  new upstream releases
- Related: #1883490

* Wed Oct 21 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-2
- fix the tarball reference for consumption directly from upstream branch
- Related: #1883490

* Wed Oct 21 2020 Jindrich Novy <jnovy@redhat.com> - 2.1.1-1
- synchronize with stream-container-tools-rhel8
- Related: #1883490

* Fri Sep 11 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.5-4
- consume content directly from the dedicated upstream branch
- Related: #1877187

* Thu Sep 10 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.5-3
- fix "[FJ8.3 Bug]: [REG] "--oom-score-adj" flag is ignored in "podman run" and "podman create""
- Resolves: #1877187

* Thu Aug 27 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.5-2
- fix gating test errors - thanks for patches to Ed Santiago
- Related: #1872263

* Thu Aug 27 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.5-1
- update to https://github.com/containers/podman/releases/tag/v2.0.5
- Resolves: #1872263

* Thu Aug 20 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.4-3
- fix "podman run namespace in man page ambiguous"
- Resolves: #1860126

* Tue Aug 11 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.4-2
- propagate proper CFLAGS to CGO_CFLAGS to assure code hardening and optimization
- Related: #1821193

* Sat Aug 01 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.4-1
- update to https://github.com/containers/podman/releases/tag/v2.0.4
- Related: #1821193

* Fri Jul 31 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.3-2
- fix "Podman build from url failed to get correct temp directory for store files"
- Resolves: #1858862

* Thu Jul 23 2020 Lokesh Mandvekar <lsm5@redhat.com> - 2.0.3-1
- update to https://github.com/containers/podman/releases/tag/v2.0.3
- Resolves: #1785242 - podman-docker Provides: docker 
- Resolves: #1804195

* Fri Jul 17 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.2-3
- fix "CVE-2020-14040 podman: golang.org/x/text: possibility to trigger an infinite loop in encoding/unicode could lead to crash [rhel-8]"
- Resolves: #1854718

* Wed Jul 15 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.2-2
- always pull in catatonit with podman and vice versa
- Related: #1821193

* Wed Jul 08 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.2-1
- update to https://github.com/containers/libpod/releases/tag/v2.0.2
- Related: #1821193

* Thu Jul 02 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.1-3
- include catatonit
- Related: #1821193

* Wed Jul 01 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.1-2
- fix "Podman does not use --tmpdir when pulling an image"
- Resolves: #1769918

* Fri Jun 26 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.1-1
- update to https://github.com/containers/libpod/releases/tag/v2.0.1
- Related: #1821193

* Mon Jun 22 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-1
- update to https://github.com/containers/libpod/releases/tag/v2.0.0
- Related: #1821193

* Thu Jun 18 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.9.rc7
- update to https://github.com/containers/libpod/releases/tag/v2.0.0-rc7
- Related: #1821193

* Tue Jun 16 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.8.rc6
- attempt to fix test user for gating tests (Ed Santiago)
- Related: #1821193

* Tue Jun 16 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.7.rc6
- fix "Socket-activated Varlink (io.podman.socket) fails after first call"
- Related: #1821193

* Tue Jun 16 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.6.rc6
- fix build: add relevant socket/service/conf files and re-enable varlink
- Related: #1821193

* Mon Jun 15 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.5.rc6
- update to https://github.com/containers/libpod/releases/tag/v2.0.0-rc6
- Related: #1821193

* Wed Jun 10 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.4.rc5
- update to https://github.com/containers/libpod/releases/tag/v2.0.0-rc5
- Related: #1821193

* Thu Jun 04 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.3.rc4
- update to https://github.com/containers/libpod/releases/tag/v2.0.0-rc4
- Related: #1821193

* Thu Jun 04 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.2.rc3
- podman-tests requires nmap-ncat now
- Related: #1821193

* Tue Jun 02 2020 Jindrich Novy <jnovy@redhat.com> - 2.0.0-0.1.rc3
- update to https://github.com/containers/libpod/releases/tag/v2.0.0-rc3
- Related: #1821193

* Mon Jun 01 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.3-3
- fix "Signature verification incorrectly uses mirror’s references"
- Related: #1821193

* Wed May 27 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.3-2
- exclude i686 arch due to "No matching package to install: 'golang >= 1.12.12-4'" on i686
- Related: #1821193

* Mon May 25 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.3-1
- update to https://github.com/containers/libpod/releases/tag/v1.9.3
- Related: #1821193

* Wed May 20 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.2-3
- fix "Podman support for FIPS Mode requires a bind mount inside the container"
- version the oci-systemd-hook obsolete
- Related: #1821193

* Tue May 19 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.2-2
- obsolete oci-systemd-hook package
- Related: #1821193

* Thu May 14 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.2-1
- update to https://github.com/containers/libpod/releases/tag/v1.9.2
- Related: #1821193

* Tue May 12 2020 Jindrich Novy <jnovy@redhat.com> - 1.9.1-1
- synchronize containter-tools 8.3.0 with 8.2.1
- Related: #1821193

* Wed Apr 01 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-11
- fix "CVE-2020-10696 buildah: crafted input tar file may lead to local file overwriting during image build process"
- Resolves: #1819812

* Thu Mar 19 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-10
- use the full PR 5348 to fix "no route to host from inside container"
- Resolves: #1806901

* Fri Mar 06 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-9
- update fix for "podman (1.6.4) rhel 8.1 no route to host from inside container"
- Resolves: #1806901

* Fri Mar 06 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-8
- fix "[FJ8.2 Bug]: [REG]The "--group-add" option of "podman create" doesn't function."
- Resolves: #1808707

* Thu Feb 27 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-7
- fix "podman (1.6.4) rhel 8.1 no route to host from inside container"
- Resolves: #1806901

* Fri Feb 21 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-6
- fix CVE-2020-1726
- Resolves: #1801571

* Wed Feb 19 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-5
- fix "Podman support for FIPS Mode requires a bind mount inside the container"
- Resolves: #1804195

* Mon Feb 17 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-4
- fix CVE-2020-1702
- Resolves: #1801924

* Wed Jan 08 2020 Jindrich Novy <jnovy@redhat.com>
- merge podman-manpages with podman package and put man pages for
  podman-remote to its dedicated subpackage
Resolves: #1788539

* Fri Jan 03 2020 Jindrich Novy <jnovy@redhat.com> - 1.6.4-2
- apply fix for #1757845
- Related: RHELPLAN-25139

* Wed Dec 11 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.4-1
- update to 1.6.4
- Related: RHELPLAN-25139

* Sat Dec 07 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-6
- remove BR: device-mapper-devel, minor spec file changes
- Related: RHELPLAN-25139

* Tue Dec 03 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-5
- Ensure volumes reacquire locks on state refresh (thanks Matt Heon)
- Related: RHELPLAN-25139

* Fri Nov 29 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-4
- use the file events logger backend if systemd isn't available
  (thanks to Giuseppe Scrivano)
- Related: RHELPLAN-25139

* Thu Nov 21 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-3
- require slirp4netns >= 0.4.0-1
- Resolves: #1766774

* Tue Nov 19 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-2
- apply fix to not to fail gating tests:
  don't parse the config for cgroup-manager default
- don't hang while on podman run --rm - bug 1767663
- Related: RHELPLAN-25139

* Mon Nov 18 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.3-1
- update to podman 1.6.3
- addresses CVE-2019-18466
- Related: RHELPLAN-25139

* Fri Nov 08 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-6
- fix %%gobuild macro to not to ignore BUILDTAGS
- Related: RHELPLAN-25139

* Tue Nov 05 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-5
- use btrfs_noversion to really disable BTRFS support
- amend/reuse BUILDTAGS
- still keep device-mapper-devel BR otherwise build fails
  despite dm support being disabled (build scripting invokes
  pkg-config for devmapper which is shipped by the dm-devel
  package)
- Related: RHELPLAN-25139

* Mon Nov 04 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-4
- disable BTRFS support
- Related: RHELPLAN-25139

* Mon Nov 04 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-3
- split podman and conmon packages
- drop BR: device-mapper-devel and update BRs in general
- Related: RHELPLAN-25139

* Fri Nov 01 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-2
- drop oci-systemd-hook requirement
- drop upstreamed CVE-2019-10214 patch
- Related: RHELPLAN-25139

* Tue Oct 29 2019 Jindrich Novy <jnovy@redhat.com> - 1.6.2-1
- update to podman 1.6.2

* Wed Oct 16 2019 Jindrich Novy <jnovy@redhat.com> - 1.4.2-6
- fix build with --nocheck (#1721394)
- escape commented out macros

* Thu Sep 12 2019 Jindrich Novy <jnovy@redhat.com> - 1.4.2-5
- Fix CVE-2019-10214 (#1734649).

* Tue Sep 03 2019 Jindrich Novy <jnovy@redhat.com> - 1.4.2-4
- update to latest conmon (Resolves: #1743685)

* Wed Aug 28 2019 Jindrich Novy <jnovy@redhat.com> - 1.4.2-3
- update to v1.4.2-stable1
- Resolves: #1741157

* Wed Jun 19 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.2-2
- Resolves: #1669197, #1705763, #1737077, #1671622, #1723879, #1730281,
- Resolves: #1731117
- built libpod v1.4.2-stable1

* Wed Jun 19 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.2-1
- Resolves: #1721638
- bump to v1.4.2

* Mon Jun 17 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.1-4
- Resolves: #1720654 - update dep on libvarlink
- Resolves: #1721247 - enable fips mode

* Mon Jun 17 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.1-3
- Resolves: #1720654 - podman requires podman-manpages
- update dep on cni plugins >= 0.8.1-1

* Sat Jun 15 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.1-2
- Resolves: #1720654 - podman-manpages obsoletes podman < 1.4.1-2

* Sat Jun 15 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.1-1
- Resolves: #1720654 - bump to v1.4.1
- bump conmon to v0.3.0

* Fri Jun 14 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.4.0-1
- Resolves: #1720654 - bump to v1.4.0

* Fri Jun 07 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.3.2-2
- Resolves: #1683217 - tests subpackage requires slirp4netns

* Fri May 31 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.3.2-1
- Resolves: #1707220 - bump to v1.3.2
- built conmon v0.2.0

* Wed Apr  3 2019 Eduardo Santiago <santiago@redhat.com> - 1.2.0-1.git3bd528e5
- package system tests, zsh completion. Update CI tests to use new -tests pkg

* Thu Feb 28 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.1.0-1.git006206a
- bump to v1.1.0

* Fri Feb 22 2019 Lokesh Mandvekar <lsm5@redhat.com> - 1.0.1-1.git2c74edd
- bump to v1.0.1

* Mon Feb 11 2019 Frantisek Kluknavsky <fkluknav@redhat.com> - 1.0.0-2.git921f98f
- rebase

* Tue Jan 15 2019 Frantisek Kluknavsky <fkluknav@redhat.com> - 1.0.0-1.git82e8011
- rebase to v1, yay!
- rebase conmon to 9b1f0a08285a7f74b21cc9b6bfd98a48905a7ba2
- Resolves:#1623282
- python interface removed, moved to https://github.com/containers/python-podman/

* Tue Dec 18 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.12.1.2-4.git9551f6b
- re-enable debuginfo

* Mon Dec 17 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.12.1.2-3.git9551f6b
- python libraries added
- resolves: #1657180

* Mon Dec 17 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.12.1.2-2.git9551f6b
- rebase

* Mon Dec 17 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.11.1.1-3.git594495d
- go tools not in scl anymore

* Mon Nov 19 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.11.1.1-2.git594495d
- fedora-like buildrequires go toolset

* Sat Nov 17 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1.1-1.git594495d
- Resolves: #1636230 - build with FIPS enabled golang toolchain
- bump to v0.11.1.1
- built commit 594495d

* Fri Nov 16 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.11.1-3.gita4adfe5
- podman-docker provides docker
- Resolves: #1650355

* Thu Nov 15 2018 Lumír Balhar <lbalhar@redhat.com> - 0.11.1-2.gita4adfe5
- Require platform-python-setuptools instead of python3-setuptools
- Resolves: rhbz#1650144

* Tue Nov 13 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.11.1-1.gita4adfe5
- bump to v0.11.1
- built libpod commit a4adfe5
- built conmon from cri-o commit 464dba6

* Fri Oct 19 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.3-5.gitdb08685
- Resolves: #1625384 - keep BR: device-mapper-devel but don't build with it
- not having device-mapper-devel seems to have brew not recognize %%{_unitdir}

* Thu Oct 18 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.3-4.gitdb08685
- Resolves: #1625384 - correctly add buildtags to remove devmapper

* Thu Oct 18 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.3-3.gitdb08685
- Resolves: #1625384 - build without device-mapper-devel (no podman support) and lvm2

* Wed Oct 17 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.3-2.gitdb08685
- Resolves: #1625384 - depend on lvm2

* Wed Oct 17 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.3-1.gitdb08685
- Resolves: #1640298 - update vendored buildah to allow building when there are
running containers
- bump to v0.10.1.3
- built podman commit db08685

* Wed Oct 17 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.2-1.git2b4f8d1
- Resolves: #1625378
- bump to v0.10.1.2
- built podman commit 2b4f8d1

* Tue Oct 16 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1.1-1.git4bea3e9
- bump to v0.10.1.1
- built podman commit 4bea3e9

* Thu Oct 11 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.10.1-1.gite4a1553
- bump podman to v0.10.1
- built podman commit e4a1553
- built conmon from cri-o commit a30f93c

* Tue Oct 09 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.9.3.1-4.git1cd906d
- rebased cri-o to 1.11.6

* Wed Sep 26 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.9.3.1-3.git1cd906d
- rebase

* Tue Sep 18 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.9.2-2.git37a2afe
- rebase to podman 0.9.2
- rebase to cri-o 0.11.4

* Tue Sep 11 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.9.1.1-2.git123de30
- rebase

* Mon Aug 27 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.4-1.git9f9b8cf
- bump to v0.8.4
- built commit 9f9b8cf
- upstream username changed from projectatomic to containers
- use containernetworking-plugins >= 0.7.3-5

* Mon Aug 13 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.2.1-2.git7a526bb
- Resolves: #1615607 - rebuild with gobuild tag 'no_openssl'

* Sun Aug 12 2018 Dan Walsh <dwalsh@redhat.com> - 0.8.2.1-1.git7a526bb
- Upstream 0.8.2.1 release
- Add support for podman-docker
Resolves: rhbz#1615104

* Fri Aug 10 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.2-1.dev.git8b2d38e
- Resolves: #1614710 - podman search name includes registry
- bump to v0.8.2-dev
- built libpod commit 8b2d38e
- built conmon from cri-o commit acc0ee7

* Wed Aug 8 2018 Dan Walsh <dwalsh@redhat.com> - 0.8.1-2.git6b4ab2a
- Add recommends for slirp4netns and container-selinux

* Tue Aug 07 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.8.1-2.git6b4ab2a
- bump to v0.8.1
- use %%go{build,generate} instead of go build and go generate
- update go deps to use scl-ized builds
- No need for Makefile patch for python installs

* Sat Aug 4 2018 Dan Walsh <dwalsh@redhat.com> - 0.8.1-1.git6b4ab2a
- Bump to v0.8.1

* Wed Aug 1 2018 Dan Walsh <dwalsh@redhat.com> - 0.7.4-2.git079121
- podman should not require atomic-registries

* Tue Jul 24 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.7.4-1.dev.git9a18681
- bump to v0.7.4-dev
- built commit 9a18681

* Sat Jul 21 2018 Dan Walsh <dwalsh@redhat.com> - 0.7.3-2.git079121
- Turn on ostree support
- Upstream 0.7.3

* Sat Jul 14 2018 Dan Walsh <dwalsh@redhat.com> - 0.7.2-2.git4ca4c5f
- Upstream 0.7.2 release

* Wed Jul 11 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.7.1-3.git84cfdb2
- rebuilt

* Wed Jul 11 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.7.1-2.git84cfdb2
- rebase to 84cfdb2

* Sun Jul 08 2018 Dan Walsh <dwalsh@redhat.com> - 0.7.1-1.git802d4f2
- Upstream 0.7.1 release

* Mon Jun 25 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.6.4-2.gitd5beb2f
- disable devel and unittest subpackages
- include conditionals for rhel-8.0

* Fri Jun 22 2018 Dan Walsh <dwalsh@redhat.com> - 0.6.4-1.gitd5beb2f
- do not compress debuginfo with dwz to support delve debugger

* Mon Jun 04 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.6.1-3.git3e0ff12
- do not compress debuginfo with dwz to support delve debugger

* Mon Jun 04 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.6.1-2.git3e0ff12
- bash completion shouldn't have shebang

* Mon Jun 04 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.6.1-1.git3e0ff12
- Resolves: #1584429 - drop capabilities when running a container as non-root
- bump to v0.6.1
- built podman commit 3e0ff12
- built conmon from cri-o commit 1c0c3b0
- drop containernetworking-plugins subpackage, it's now split out into a standalone
package

* Fri Apr 27 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.4.1-4.gitb51d327
- Resolves: #1572538 - build host-device and portmap plugins

* Thu Apr 12 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.4.1-3.gitb51d327
- correct dep on containernetworking-plugins

* Thu Apr 12 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.4.1-2.gitb51d327
- add containernetworking-plugins v0.7.0 as a subpackage (podman dep)
- release tag for the containernetworking-plugins is actually gotten from
podman release tag.

* Wed Apr 11 2018 Lokesh Mandvekar <lsm5@redhat.com> - 0.4.1-1.gitb51d327
- bump to v0.4.1
- built commit b51d327

* Wed Mar 14 2018 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.3.3-1.dev.gitbc358eb
- built podman commit bc358eb
- built conmon from cri-o commit 712f3b8

* Fri Mar 09 2018 baude <bbaude@redhat.com> - 0.3.2-1.gitf79a39a
- Release 0.3.2-1

* Sun Mar 04 2018 baude <bbaude@redhat.com> - 0.3.1-2.git98b95ff
- Correct RPM version

* Fri Mar 02 2018 baude <bbaude@redhat.com> - 0.3.1-1-gitc187538
- Release 0.3.1-1

* Sun Feb 25 2018 Peter Robinson <pbrobinson@fedoraproject.org> 0.2.2-2.git525e3b1
- Build on ARMv7 too (Fedora supports containers on that arch too)

* Fri Feb 23 2018 baude <bbaude@redhat.com> - 0.2.2-1.git525e3b1
- Release 0.2.2

* Fri Feb 16 2018 baude <bbaude@redhat.com> - 0.2.1-1.git3d0100b
- Release 0.2.1

* Wed Feb 14 2018 baude <bbaude@redhat.com> - 0.2-3.git3d0100b
- Add dep for atomic-registries

* Tue Feb 13 2018 baude <bbaude@redhat.com> - 0.2-2.git3d0100b
- Add more 64bit arches
- Add containernetworking-cni dependancy
- Add iptables dependancy

* Mon Feb 12 2018 baude <bbaude@redhat.com> - 0-2.1.git3d0100
- Release 0.2

* Tue Feb 06 2018 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0-0.3.git367213a
- Resolves: #1541554 - first official build
- built commit 367213a

* Fri Feb 02 2018 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0-0.2.git0387f69
- built commit 0387f69

* Wed Jan 10 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0-0.1.gitc1b2278
- First package for Fedora
