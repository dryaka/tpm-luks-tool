%if 0%{?rhel} == 9
%global python3_pkgversion 3.11
%endif

Name:           tpm-luks-tool
Version:        0.4.0
Release:        1%{?dist}
Summary:        Policy-driven TPM2-bound LUKS2 management tool

License:        GPL-3.0-or-later
URL:            https://github.com/dryaka/tpm-luks-tool
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  pyproject-rpm-macros
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-pip
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-wheel
%if 0%{?rhel} == 9
BuildRequires:  python3.11-rpm-macros
%endif

Requires:       cryptsetup
Requires:       systemd
Requires:       python%{python3_pkgversion} >= 3.11

%description
tpm-luks-tool is a small policy-driven Linux administration tool for
managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.
It separates PCR trust approval, TPM enrollment reconciliation, reboot
verification, and cleanup of obsolete TPM enrollments.

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files tpm_luks

install -Dpm 0644 examples/tpm-luks.toml %{buildroot}%{_sysconfdir}/tpm-luks.toml

%check
PYTHONPATH=src %{python3} -m unittest discover -s tests -v

%files -f %{pyproject_files}
%license LICENSE
%doc AUTHORS
%doc README.md
%doc docs/architecture.md
%doc docs/packaging.md
%config(noreplace) %{_sysconfdir}/tpm-luks.toml
%{_bindir}/tpm-luks

%changelog
* Sun Oct 04 2026 Aleš Dryák <ales.dryak@volny.cz> - 0.4.0-1
- Add initial native RPM packaging.
