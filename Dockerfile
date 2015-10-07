FROM httpd:2.4
MAINTAINER William Budington <bill@eff.org>

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    python-crypto \
    python-minimal && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

ADD cryptolog.py /usr/bin/cryptolog
RUN sed -i 's/^[^#]*CustomLog.\+$/CustomLog "| \/usr\/bin\/cryptolog -w \/proc\/self\/fd\/1" combined/g' /usr/local/apache2/conf/httpd.conf
