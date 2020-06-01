FROM node:lts as build-deps
WORKDIR /usr/src/app
ARG REACT_APP_GORTAS_URL=http://localhost:8080
ENV REACT_APP_GORTAS_URL=${REACT_APP_GORTAS_URL}
ARG REACT_APP_GORTAS_SIGN_UP_PATH=/gortas/v1/login/users/registration
ENV REACT_APP_GORTAS_SIGN_UP_PATH=${REACT_APP_GORTAS_SIGN_UP_PATH}
ARG REACT_APP_GORTAS_SIGN_IN_PATH=/gortas/v1/login/users/login
ENV REACT_APP_GORTAS_SIGN_IN_PATH=${REACT_APP_GORTAS_SIGN_IN_PATH}
RUN git clone https://github.com/maximthomas/gortas-ui.git .
RUN yarn && yarn build

FROM nginx:1.17-alpine
COPY --from=build-deps /usr/src/app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]