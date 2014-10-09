Name:           dbxtool
Version:        0.6
Release:        1%{?dist}
Summary:        Secure Boot DBX updater
License:        GPLv2
URL:            https://github.com/vathpela/dbxtool
ExclusiveArch:  i386 x86_64 aarch64
BuildRequires:  popt-devel git systemd
BuildRequires:  efivar-devel >= 0.14-1
Requires:       efivar >= 0.14-1
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
git config --unset user.email
git config --unset user.name

%build
make PREFIX=%{_prefix} LIBDIR=%{_libdir} CFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}/%{_libdir}
make PREFIX=%{_prefix} LIBDIR=%{_libdir} INSTALLROOT=%{buildroot} \
        install
rm -f %{buildroot}/%{_docdir}/%{name}/COPYING

%files
%{!?_licensedir:%global license %%doc}
%license COPYING
%{_bindir}/dbxtool
%doc %{_mandir}/man1/*
%dir %{_datadir}/dbxtool/
%{_datadir}/dbxtool/*.bin
%{_unitdir}/dbxtool.service

%changelog
* Wed Oct 08 2014 Peter Jones <pjones@redhat.com> - 0.6-1
- Update to 0.6
- make "dbxtool -l" correctly show not-well-known guids.

* Tue Oct 07 2014 Peter Jones <pjones@redhat.com> - 0.5-1
- Update to 0.5:
- make applying to dbx when it doesn't exist work (lersek)
- make displaying KEK work right

* Wed Aug 20 2014 Peter Jones <pjones@redhat.com> - 0.4-1
- First packaging attempt.
