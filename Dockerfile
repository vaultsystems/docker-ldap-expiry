FROM python:2-alpine3.7

RUN apk update
RUN apk add --virtual build-dependencies python-dev build-base wget openldap-dev

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app
WORKDIR /app
COPY ./ldap-expiry.py /app

CMD [ "python", "/app/ldap-expiry.py" ]

