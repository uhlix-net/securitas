# Securitas agent for Linux: the compliance-check wrapper, Goss and a setup command.
# Built by the Securitas Dockerfile (stage "agent"); version and Goss are passed in with --define.
Name:           securitas-agent
Version:        %{agent_version}
Release:        1%{?dist}
Summary:        Securitas agent: lets Securitas run CIS compliance checks on this host
License:        Apache-2.0
URL:            https://github.com/uhlix-net/securitas
Source0:        securitas-cis-audit
Source1:        securitas-agent-setup
Source2:        goss
Source3:        LICENSE
Requires:       sudo, tar, gzip, coreutils, findutils, openssh-server, shadow-utils
ExclusiveArch:  x86_64
%global debug_package %{nil}
%global __strip /bin/true

%description
Installs what Securitas needs to check this host against CIS benchmarks:
- /usr/local/sbin/securitas-cis-audit: runs Goss read-only on the audit content Securitas copies at scan time
  (unpacked as root into a root-only random hidden directory in /tmp and deleted afterwards), prints JSON
- /usr/libexec/securitas-agent/goss: Goss %{goss_version} (goss-org, checksum-pinned at build time)
- /usr/sbin/securitas-agent-setup: creates the scan account, authorizes Securitas's SSH key and adds the one
  sudo rule (the account may run only the wrapper). Run by the install script Securitas serves.
Whoever controls Securitas decides what Goss runs as root on this host.

%install
install -D -m 0755 %{SOURCE0} %{buildroot}/usr/local/sbin/securitas-cis-audit
install -D -m 0755 %{SOURCE1} %{buildroot}/usr/sbin/securitas-agent-setup
install -D -m 0755 %{SOURCE2} %{buildroot}/usr/libexec/securitas-agent/goss
install -D -m 0644 %{SOURCE3} %{buildroot}/usr/share/licenses/%{name}/LICENSE

%postun
# on erase (not upgrade): remove the sudo rule and settings; the account and its key are kept
if [ "$1" = 0 ]; then
  rm -f /etc/sudoers.d/securitas-agent /etc/securitas-agent.conf
fi

%files
/usr/local/sbin/securitas-cis-audit
/usr/sbin/securitas-agent-setup
%dir /usr/libexec/securitas-agent
/usr/libexec/securitas-agent/goss
%license /usr/share/licenses/%{name}/LICENSE
%ghost %config(noreplace) /etc/securitas-agent.conf
%ghost /etc/sudoers.d/securitas-agent
