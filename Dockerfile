FROM python:3.6-stretch
ENV DEBIAN_FRONTEND noninteractive
ENV DOCKER_BUILD 1
WORKDIR /usr/src/app

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser -d /usr/src/app
RUN chown appuser.appuser /usr/src/app

RUN apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends \
					build-essential \
					libunbound-dev \
					libidn11-dev \
					libssl-dev \
					libtool \
					m4 \
					autoconf \
					apt-utils \
	&& rm -rf /var/lib/apt/lists/*
RUN wget https://getdnsapi.net/dist/getdns-1.3.0.tar.gz \
					&& echo '920fa2e07c72fd0e5854db1820fa777108009fc5cb702f9aa5155ef58b12adb1 getdns-1.3.0.tar.gz' | sha256sum -c \
                                        && tar -xzf getdns-1.3.0.tar.gz \
                                        && cd getdns-1.3.0 \
                                        && ./configure \
                                        && make \
                                        && make install
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY * /
USER appuser
CMD [ "python", "-u", "bot.py" ]
