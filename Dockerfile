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

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY plugins/ ./plugins/
COPY *.py ./
USER appuser
CMD [ "python", "-u", "bot.py" ]
