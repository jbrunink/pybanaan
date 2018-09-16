FROM python:3.6-stretch
ENV DEBIAN_FRONTEND noninteractive
ENV DOCKER_BUILD 1
WORKDIR /usr/src/app

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser -d /usr/src/app
RUN chown appuser.appuser /usr/src/app

COPY Pipfile* ./
RUN pip install pipenv

RUN pipenv install --system --deploy
COPY plugins/ ./plugins/
COPY *.py ./
USER appuser
CMD [ "python", "-u", "bot.py", "-c", "data/banaan.ini" ]
