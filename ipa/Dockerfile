FROM quay.io/freeipa/freeipa-server:fedora-rawhide

# IPA container relies on /data volume that we must create for the build
# process.

RUN cp -a /data-template/. /data/ && \
    mkdir -p /tmp/var/tmp && \
    dnf copr enable -y pbrezina/s4u && \
    dnf upgrade -y 389-ds\* freeipa-server sssd\* && \
    dnf clean all && \
    cp -a /data/. /data-template/

# Override UID_MAX and GID_MAX to allow IPA to use short ID ranges to fit into
# SUBUID ranges. Must be smaller then --idstart.
RUN sed -i -e 's/^UID_MIN.*/UID_MIN 1000/' \
           -e 's/^UID_MAX.*/UID_MAX 2000/' \
           -e 's/^GID_MIN.*/GID_MIN 1000/' \
           -e 's/^GID_MAX.*/GID_MAX 2000/' \
           /etc/login.defs
