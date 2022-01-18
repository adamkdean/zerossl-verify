# Copyright 2022 Adam K Dean <adamkdean@googlemail.com>
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

FROM node:lts AS build

COPY package*.json ./
RUN npm install

COPY src ./src
COPY tsconfig.json ./
RUN npm run build

CMD ["npm", "start"]
