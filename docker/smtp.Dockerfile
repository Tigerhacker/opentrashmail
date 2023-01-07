FROM python:3.11-alpine

EXPOSE 25
ENTRYPOINT ["python", "/mailserver.py"]

WORKDIR /
VOLUME /data

ADD ./mailserver.py /mailserver.py
