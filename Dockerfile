FROM node:16.15.0-alpine as base

FROM base as prebuild
WORKDIR /app

COPY package*.json /app/
COPY tsconfig*.json /app/

RUN npm ci --quiet

COPY src /app/src
RUN npm run build

FROM base as production

WORKDIR /app

COPY --from=prebuild /app/package*.json /app/
RUN npm install --quiet --production
COPY --from=prebuild /app/build /app/build

RUN apk --no-cache add curl
RUN apk --no-cache add bash
RUN set -ex && apk --no-cache add sudo

RUN curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash && sudo NEW_RELIC_API_KEY=NRAK-TDAW4KUECLPWDV5B6FE5W2R3JGI NEW_RELIC_ACCOUNT_ID=3558430 /usr/local/bin/newrelic install -n logs-integration

EXPOSE 80

CMD ["npm", "run", "start"]
