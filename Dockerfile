ARG IMG_ENVIRONMENT
FROM node:18-alpine as base

FROM base as prebuild
WORKDIR /app

COPY package*.json /app/
COPY tsconfig*.json /app/
COPY newrelic.js /app/
COPY vault_local /app/vault_local

RUN npm ci --quiet

COPY src /app/src
RUN npm run build

FROM base as pre-final

WORKDIR /app

COPY --from=prebuild /app/package*.json /app/
RUN npm install --quiet --production
COPY --from=prebuild /app/build /app/build

# PRODUCTION IMAGE - IMG_ENVIRONMENT=production
# FROM pre-final as img-production

COPY --from=prebuild /app/newrelic.js /app/build

RUN apk --no-cache add curl
RUN apk --no-cache add bash
RUN set -ex && apk --no-cache add sudo

RUN curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash && sudo NEW_RELIC_API_KEY=NRAK-TDAW4KUECLPWDV5B6FE5W2R3JGI NEW_RELIC_ACCOUNT_ID=3558430 /usr/local/bin/newrelic install -n logs-integration

# LOCAL IMAGE - IMG_ENVIRONMENT=local
FROM pre-final as img-local
RUN ls
COPY --from=prebuild /app/vault_local /app/vault_local

# FINAL BUILD
ARG IMG_ENVIRONMENT
FROM img-${IMG_ENVIRONMENT} as final
RUN echo BUILDING FOR [${IMG_ENVIRONMENT}] ENVIRONMENT

EXPOSE 80

CMD ["npm", "run", "start"]
