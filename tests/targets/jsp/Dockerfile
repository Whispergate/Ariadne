FROM tomcat:10-jdk17

RUN mkdir -p /usr/local/tomcat/webapps/ROOT/uploads && \
    chmod 777 /usr/local/tomcat/webapps/ROOT/uploads

COPY index.jsp /usr/local/tomcat/webapps/ROOT/index.jsp
COPY web.xml /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml

EXPOSE 8080
