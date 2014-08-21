Name:           dbxtool
Version:        0.4
Release:        1%{?dist}
Summary:        Secure Boot DBX updater
License:        GPLv2
URL:            https://github.com/vathpela/dbxtool
ExclusiveArch:  i386 x86_64 aarch64
BuildRequires:  popt-devel git efivar-devel
Source0:        https://github.com/vathpela/dbxtool/releases/download/dbxtool-%{version}/dbxtool-%{version}.tar.bz2

%description
This package contains DBX updates for UEFI Secure Boot.

%prep
%setup -q -n %{name}-%{version}
git init
git config user.email "%{name}-owner@fedoraproject.org"
git config user.name "Fedora Ninjas"
git add .
git commit -a -q -m "%{version} baseline."
git am %{patches} </dev/null

%build
make PREFIX=%{_prefix} LIBDIR=%{_libdir} CFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}/%{_libdir}
make PREFIX=%{_prefix} LIBDIR=%{_libdir} INSTALLROOT=%{buildroot} \
        install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%{!?_licensedir:%global license %%doc}
%license COPYING
%{_bindir}/dbxtool
%{_mandir}/man1/*
%dir %{_datadir}/dbxtool/
%{_datadir}/dbxtool/*.bin
%{_unitdir}/dbxtool.service
%{_mandir}/man1/*

%changelog
* Wed Aug 20 2014 Peter Jones <pjones@redhat.com> - 0.4-1
- First packaging attempt.
