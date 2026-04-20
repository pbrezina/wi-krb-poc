FROM fedora:latest

RUN dnf copr enable -y pbrezina/s4u
RUN dnf install -y \
        openssh-server \
        freeipa-client \
        sssd\* \
        oddjob \
        oddjob-mkhomedir systemd && \
    dnf clean all

RUN authselect select sssd with-gssapi with-mkhomedir --force
RUN systemctl enable sshd sssd-kcm.socket oddjobd

COPY 99-ssh-gssapi.conf /etc/ssh/sshd_config.d/99-ssh-gssapi.conf
COPY --chmod=755 --chown=root:root sss-confined-shell /usr/bin/sss-confined-shell

RUN sed -i -e 's/^UID_MIN.*/UID_MIN 1000/' \
           -e 's/^UID_MAX.*/UID_MAX 2000/' \
           -e 's/^GID_MIN.*/GID_MIN 1000/' \
           -e 's/^GID_MAX.*/GID_MAX 2000/' \
           /etc/login.defs

# For demonstration
RUN touch /root/only-root-can-see

ENTRYPOINT [ "/usr/sbin/init" ]
STOPSIGNAL RTMIN+3
