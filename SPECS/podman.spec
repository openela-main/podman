%global with_debug 1

%if 0%{?with_debug}
%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0
%else
%global debug_package %{nil}
%endif

# https://issues.redhat.com/browse/RHEL-56365
%global sequoia 1

%global import_path github.com/containers/podman
#%%global branch v5.6-rhel
%global commit0 a476c2b2c35443a3db1a1668ac7b402eb1eb0619
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

%global gomodulesmode GO111MODULE=on

%if %{defined fedora}
%define build_with_btrfs 1
# qemu-system* isn't packageed for CentOS Stream / RHEL
%define qemu 1
%endif

%if %{defined copr_username}
%define copr_build 1
%endif

# Only RHEL and CentOS Stream rpms are built with fips-enabled go compiler
%if %{defined rhel}
%define fips_enabled 1
%endif

%global container_base_path github.com/containers
%global container_base_url https://%{container_base_path}

# For LDFLAGS
%global ld_project %{container_base_path}/%{name}/v5
%global ld_libpod %{ld_project}/libpod

# %%{name}
%global git0 %{container_base_url}/%{name}

# podman-machine subpackage will be present only on these architectures
%global machine_arches x86_64 aarch64

%if %{defined copr_build}
%define build_origin Copr: %{?copr_username}/%{?copr_projectname}
%else
%define build_origin %{?packager}
%endif

Name: podman
%if %{defined copr_build}
Epoch: 102
%else
Epoch: 7
%endif
# DO NOT TOUCH the Version string!
# The TRUE source of this specfile is:
# https://github.com/containers/podman/blob/main/rpm/podman.spec
# If that's what you're reading, Version must be 0, and will be updated by Packit for
# copr and koji builds.
# If you're reading this on dist-git, the version is automatically filled in by Packit.
Version: 5.8.2
# The `AND` needs to be uppercase in the License for SPDX compatibility
License: Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0
Release: 5%{?dist}
%if %{defined golang_arches_future}
ExclusiveArch: %{golang_arches_future}
%else
ExclusiveArch: aarch64 ppc64le s390x x86_64 riscv64
%endif
Summary: Manage Pods, Containers and Container Images
URL: https://%{name}.io/
# All SourceN files fetched from upstream
%if 0%{?branch:1}
Source0: https://%{import_path}/tarball/%{commit0}/%{branch}-%{shortcommit0}.tar.gz
%else
Source0: https://gitlab.cee.redhat.com/sustaining-engineering/container-tools/src-git/%{name}/-/archive/%{commit0}/%{name}-%{commit0}.tar.gz
%endif

Provides: %{name}-manpages = %{epoch}:%{version}-%{release}
BuildRequires: %{_bindir}/envsubst
%if %{defined build_with_btrfs}
BuildRequires: btrfs-progs-devel
%endif
BuildRequires: gcc
BuildRequires: glib2-devel
BuildRequires: glibc-devel
BuildRequires: glibc-static
BuildRequires: golang
BuildRequires: git-core
%if %{undefined rhel} || 0%{?rhel} >= 10
BuildRequires: go-rpm-macros
%endif
BuildRequires: gpgme-devel
BuildRequires: libassuan-devel
BuildRequires: libgpg-error-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: shadow-utils-subid-devel
BuildRequires: pkgconfig
BuildRequires: make
BuildRequires: man-db
BuildRequires: sqlite-devel
BuildRequires: systemd
BuildRequires: systemd-devel
Requires: catatonit
Requires: conmon >= 2:2.1.7-2
%if %{defined fedora} && 0%{?fedora} >= 40
# TODO: Remove the f40 conditional after a few releases to keep conditionals to
# a minimum
# Ref: https://bugzilla.redhat.com/show_bug.cgi?id=2269148
Requires: containers-common-extra >= 5:0.58.0-1
%else
Requires: containers-common-extra
%endif
%if %{defined sequoia}
Requires: podman-sequoia
%endif

Obsoletes: %{name}-quadlet <= 5:4.4.0-1
Provides: %{name}-quadlet = %{epoch}:%{version}-%{release}

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


%package docker
Summary: Emulate Docker CLI using %{name}
BuildArch: noarch
Requires: %{name} = %{epoch}:%{version}-%{release}
Conflicts: docker
Conflicts: docker-latest
Conflicts: docker-ce
Conflicts: docker-ee
Conflicts: moby-engine

%description docker
This package installs a script named docker that emulates the Docker CLI by
executes %{name} commands, it also creates links between all Docker CLI man
pages and %{name}.

%package tests
Summary: Tests for %{name}

Requires: %{name} = %{epoch}:%{version}-%{release}
%if %{defined distro_bats}
Requires: bats
%endif
Requires: attr
Requires: jq
Requires: skopeo
Requires: nmap-ncat
Requires: httpd-tools
Requires: openssl
Requires: socat
Requires: slirp4netns
Requires: buildah
Requires: gnupg
Requires: xfsprogs

%description tests
%{summary}

This package contains system tests for %{name}. Only intended to be used for
gating tests. Not supported for end users / customers.

%package remote
Summary: (Experimental) Remote client for managing %{name} containers

%description remote
Remote client for managing %{name} containers.

This experimental remote client is under heavy development. Please do not
run %{name}-remote in production.

%{name}-remote uses the version 2 API to connect to a %{name} client to
manage pods, containers and container images. %{name}-remote supports ssh
connections as well.

%package -n %{name}sh
Summary: Confined login and user shell using %{name}
Requires: %{name} = %{epoch}:%{version}-%{release}
Provides: %{name}-shell = %{epoch}:%{version}-%{release}
Provides: %{name}-%{name}sh = %{epoch}:%{version}-%{release}

%description -n %{name}sh
%{name}sh provides a confined login and user shell with access to volumes and
capabilities specified in user quadlets.

It is a symlink to %{_bindir}/%{name} and execs into the `%{name}sh` container
when `%{_bindir}/%{name}sh` is set as a login shell or set as os.Args[0].

%ifarch %{machine_arches}
%package machine
Summary: Metapackage for setting up %{name} machine
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires: gvisor-tap-vsock
%if %{defined qemu}
%ifarch aarch64
Requires: qemu-system-aarch64-core
%endif
%ifarch x86_64
Requires: qemu-system-x86-core
%endif
%else
Requires: qemu-kvm
%endif
Requires: qemu-img
Requires: virtiofsd
ExclusiveArch: x86_64 aarch64

%description machine
This subpackage installs the dependencies for %{name} machine, for more see:
https://docs.podman.io/en/latest/markdown/podman-machine.1.html
%endif

%prep
%if 0%{?branch:1}
%autosetup -Sgit -n containers-%{name}-%{shortcommit0}
%else
%autosetup -Sgit -n %{name}-%{commit0}
%endif
sed -i 's;@@PODMAN@@\;$(BINDIR);@@PODMAN@@\;%{_bindir};' Makefile

# cgroups-v1 is supported on rhel9
%if 0%{?rhel} == 9
sed -i '/DELETE ON RHEL9/,/DELETE ON RHEL9/d' libpod/runtime.go
%endif

%build
%set_build_flags
export CGO_CFLAGS=$CFLAGS

# These extra flags present in $CFLAGS have been skipped for now as they break the build
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-flto=auto//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-Wp,D_GLIBCXX_ASSERTIONS//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-specs=\/usr\/lib\/rpm\/redhat\/redhat-annobin-cc1//g')

%ifarch x86_64
export CGO_CFLAGS+=" -m64 -mtune=generic -fcf-protection=full"
%endif

export GOPROXY=direct

LDFLAGS="-X %{ld_libpod}/define.buildInfo=${SOURCE_DATE_EPOCH:-$(date +%s)} \
         -X \"%{ld_libpod}/define.buildOrigin=%{build_origin}\" \
         -X %{ld_libpod}/define.gitCommit=%{commit0} \
         -X %{ld_libpod}/config._installPrefix=%{_prefix} \
         -X %{ld_libpod}/config._etcDir=%{_sysconfdir} \
         -X %{ld_project}/pkg/systemd/quadlet._binDir=%{_bindir}"

# build rootlessport first
%gobuild -o bin/rootlessport ./cmd/rootlessport

export BASEBUILDTAGS="seccomp $(hack/systemd_tag.sh) $(hack/libsubid_tag.sh) libsqlite3 grpcnotrace"


# libtrust_openssl buildtag switches to using the FIPS-compatible func
# `ecdsa.HashSign`.
# Ref 1: https://github.com/golang-fips/go/blob/main/patches/015-add-hash-sign-verify.patch#L22
# Ref 2: https://github.com/containers/libtrust/blob/main/ec_key_openssl.go#L23
%if %{defined fips_enabled}
export BASEBUILDTAGS="$BASEBUILDTAGS libtrust_openssl"
%endif

# build %%{name}
export BUILDTAGS="$BASEBUILDTAGS $(hack/btrfs_installed_tag.sh)"

%if %{defined sequoia}
export BUILDTAGS="$BUILDTAGS containers_image_sequoia"
%endif

%gobuild -o bin/%{name} ./cmd/%{name}

# build %%{name}-remote
export BUILDTAGS="$BASEBUILDTAGS exclude_graphdriver_btrfs remote"
%gobuild -o bin/%{name}-remote ./cmd/%{name}

# build quadlet
export BUILDTAGS="$BASEBUILDTAGS $(hack/btrfs_installed_tag.sh)"
%gobuild -o bin/quadlet ./cmd/quadlet

# build %%{name}-testing
export BUILDTAGS="$BASEBUILDTAGS $(hack/btrfs_installed_tag.sh)"
%gobuild -o bin/podman-testing ./cmd/podman-testing

# reset LDFLAGS for plugins binaries
LDFLAGS=''

%{__make} docs docker-docs

%install
install -dp %{buildroot}%{_unitdir}
PODMAN_VERSION=%{version} %{__make} DESTDIR=%{buildroot} PREFIX=%{_prefix} ETCDIR=%{_sysconfdir} \
       install.bin \
       install.man \
       install.systemd \
       install.completions \
       install.docker \
       install.docker-docs \
       install.remote \
       install.testing

sed -i 's;%{buildroot};;g' %{buildroot}%{_bindir}/docker

# do not include docker and podman-remote man pages in main package
for file in `find %{buildroot}%{_mandir}/man[157] -type f | sed "s,%{buildroot},," | grep -v -e %{name}sh.1 -e remote -e docker`; do
    echo "$file*" >> %{name}.file-list
done

rm -f %{buildroot}%{_mandir}/man5/docker*.5

install -d -p %{buildroot}%{_datadir}/%{name}/test/system
cp -pav test/system %{buildroot}%{_datadir}/%{name}/test/

%ifarch %{machine_arches}
# symlink virtiofsd in %%{name} libexecdir for machine subpackage
ln -s ../virtiofsd %{buildroot}%{_libexecdir}/%{name}
%if !%{defined qemu}
ln -s ../qemu-kvm %{buildroot}%{_libexecdir}/%{name}/qemu-system-%{arch}
%endif
%endif

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

# Include empty check to silence rpmlint warning
%check

%files -f %{name}.file-list
%license LICENSE vendor/modules.txt
%doc README.md CONTRIBUTING.md install.md transfer.md
%{_bindir}/%{name}
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/rootlessport
%{_libexecdir}/%{name}/quadlet
%{_datadir}/bash-completion/completions/%{name}
# By "owning" the site-functions dir, we don't need to Require zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_%{name}
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%{_unitdir}/%{name}*
%{_userunitdir}/%{name}*
%{_tmpfilesdir}/%{name}.conf
%{_systemdgeneratordir}/%{name}-system-generator
%{_systemdusergeneratordir}/%{name}-user-generator
# iptables modules are only needed with iptables-legacy,
# as of f41 netavark will default to nftables so do not load unessary modules
# https://fedoraproject.org/wiki/Changes/NetavarkNftablesDefault
%if %{defined fedora} && 0%{?fedora} < 41
%{_modulesloaddir}/%{name}-iptables.conf
%endif

%files docker
%{_bindir}/docker
%{_mandir}/man1/docker*.1*
%{_sysconfdir}/profile.d/%{name}-docker.*
%{_tmpfilesdir}/%{name}-docker.conf
%{_user_tmpfilesdir}/%{name}-docker.conf

%files remote
%license LICENSE
%{_bindir}/%{name}-remote
%{_mandir}/man1/%{name}-remote*.*
%{_datadir}/bash-completion/completions/%{name}-remote
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/%{name}-remote.fish
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_%{name}-remote

%files tests
%{_bindir}/%{name}-testing
%{_datadir}/%{name}/test

%files -n %{name}sh
%{_bindir}/%{name}sh
%{_mandir}/man1/%{name}sh.1*

%ifarch %{machine_arches}
%files machine
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/virtiofsd
%if !%{defined qemu}
%{_libexecdir}/%{name}/qemu-system-%{arch}
%endif
%endif

%changelog
* Fri Jul 10 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.2-5
- rebuild for CVE-2026-39822
- Resolves: RHEL-193642

* Wed Jul 08 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.2-4
- update to the latest state of the sustaining branch
- fixes CVE-2026-42508 CVE-2026-39829 CVE-2026-39830 CVE-2026-39832 CVE-2026-39835
- fixes CVE-2026-57231 CVE-2026-25681 CVE-2026-27136
- Resolves: RHEL-173842 RHEL-185604 RHEL-185920 RHEL-186263 RHEL-188713 RHEL-190073 RHEL-190857 RHEL-191095 RHEL-191546 RHEL-192440

* Thu May 07 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.2-3
- Rebuild for CVE-2026-32283
- Resolves: RHEL-167501

* Mon May 04 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.2-2
- Rebuild for CVE-2026-25679
- Resolves: RHEL-158493

* Thu Apr 16 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.2-1
- update to https://github.com/containers/podman/releases/tag/v5.8.2
- fixes CVE-2026-34986 go-jose: Go JOSE Denial of Service via crafted JWE
- Resolves: RHEL-165012

* Mon Mar 30 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.1-1
- update to https://github.com/containers/podman/releases/tag/v5.8.1
- fixes Update Podman to support TLS 1.3 configuration
- Resolves: RHEL-153732

* Mon Feb 16 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.0-2
- enable sequoia
- Resolves: RHEL-56365

* Fri Feb 13 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.8.0-1
- update to https://github.com/containers/podman/releases/tag/v5.8.0
- Related: RHEL-122178

* Thu Jan 29 2026 Jindrich Novy <jnovy@redhat.com> - 7:5.6.0-30
- update to rhel-10.1.z version of podman
- Related: RHEL-111917

* Fri Aug 22 2025 Jindrich Novy <jnovy@redhat.com> - 7:5.6.0-2
- update to the latest content of https://github.com/containers/podman/tree/v5.6-rhel
  (https://github.com/containers/podman/commit/56f1962)
- fixes "Work on RHEL10.1 packaging"
- Related: RHEL-80817

* Wed Aug 20 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.6.1-0.1
- update to the latest content of https://github.com/containers/podman/tree/v5.6
  (https://github.com/containers/podman/commit/d46b857)
- fixes "Can not find network create and rm message from podman event when set --events-backend to journald"
- Related: RHEL-109790

* Fri Aug 15 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.6.0-1
- update to https://github.com/containers/podman/releases/tag/v5.6.0
- Related: RHEL-80817

* Thu Jul 03 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.5.2-1
- update to https://github.com/containers/podman/releases/tag/v5.5.2
- Related: RHEL-80817

* Tue Jun 10 2025 Lokesh Mandvekar <lsm5@redhat.com> - 6:5.5.1-2
- Remove copr related seds from spec
- Related: RHEL-80817

* Mon Jun 09 2025 Jindrich Novy - 6:5.5.1-1
- update to https://github.com/containers/podman/releases/tag/v5.5.1
- Related: RHEL-80817

* Fri May 02 2025 Lokesh Mandvekar <lsm5@redhat.com> - 6:5.4.0-7
- Switch to TMT for gating tests
- Resolves: RHEL-80817

* Mon Apr 07 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-6
- update to the latest content of https://github.com/containers/podman/tree/v5.4-rhel
  (https://github.com/containers/podman/commit/a994a04)
- fixes "podman tests are failing"
- Resolves: RHEL-85826

* Fri Apr 04 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-5
- update to the latest content of https://github.com/containers/podman/tree/v5.4-rhel
  (https://github.com/containers/podman/commit/f7bf65c)
- fixes "Work on RHEL10.1 packaging"
- Related: RHEL-80817

* Tue Mar 18 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-4
- update to the latest content of https://github.com/containers/podman/tree/v5.4-rhel
  (https://github.com/containers/podman/commit/9ad4842)
- fixes "CVE-2025-22869 podman: Denial of Service in the Key Exchange of golang.org/x/crypto/ssh [rhel-10.0]"
- Resolves: RHEL-82776

* Thu Mar 13 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-3
- update to the latest content of https://github.com/containers/podman/tree/v5.4-rhel
  (https://github.com/containers/podman/commit/45c2d1f)
- fixes "CVE-2025-27144 podman: Go JOSE's Parsing Vulnerable to Denial of Service [rhel-10.1]"
- Resolves: RHEL-80610

* Fri Mar 07 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-2
- update to the latest content of https://github.com/containers/podman/tree/v5.4-rhel
  (https://github.com/containers/podman/commit/5e3accd)
- Related: RHEL-80817

* Wed Feb 12 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.4.0-1
- update to https://github.com/containers/podman/releases/tag/v5.4.0
- Related: RHEL-58990

* Wed Jan 22 2025 Jindrich Novy <jnovy@redhat.com> - 6:5.3.2-1
- update to https://github.com/containers/podman/releases/tag/v5.3.2
- Related: RHEL-58990

* Mon Dec 02 2024 Jindrich Novy <jnovy@redhat.com> - 6:5.3.1-3
- Do not use ExcludeArch for machine but ifarch conditionals
- Resolves: RHEL-69441

* Thu Nov 28 2024 Jindrich Novy <jnovy@redhat.com> - 6:5.3.1-2
- Reduce arches for podman-machine to x86_64 aarch64
- Resolves: RHEL-69441

* Mon Nov 25 2024 Jindrich Novy <jnovy@redhat.com> - 6:5.3.1-1
- update to https://github.com/containers/podman/releases/tag/v5.3.1
- Resolves: RHEL-24623

* Mon Nov 11 2024 Jindrich Novy <jnovy@redhat.com> - 6:5.2.2-3
- update to the latest content of https://github.com/containers/podman/tree/v5.2-rhel
  (https://github.com/containers/podman/commit/e40738b)
- Resolves: RHEL-61858

* Tue Oct 29 2024 Troy Dawson <tdawson@redhat.com> - 6:5.2.2-2
- Bump release for October 2024 mass rebuild:
  Resolves: RHEL-64018

* Wed Oct 09 2024 Jindrich Novy <jnovy@redhat.com> - 6:5.2.2-1
- stick to v5.2-rhel upstream branch for RHEL
- update to the latest content of https://github.com/containers/podman/tree/v5.2-rhel
  (https://github.com/containers/podman/commit/458f9b4)
- Related: RHEL-58990

* Tue Oct 08 2024 Jindrich Novy <jnovy@redhat.com> - 5:5.2.4-1
- update to https://github.com/containers/podman/releases/tag/v5.2.4
- Related: RHEL-61719
