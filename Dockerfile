FROM node:18

RUN apt-get update && apt-get install -y build-essential git libgmp3-dev libsodium-dev nasm curl m4

RUN git clone https://github.com/iden3/rapidsnark.git && \
    cd rapidsnark && \
    git submodule init && \
    git submodule update && \
    npm install && \
    npx task buildProver

WORKDIR /app
COPY . .

RUN yarn install

EXPOSE 4000
CMD ["node", "server.js"] 