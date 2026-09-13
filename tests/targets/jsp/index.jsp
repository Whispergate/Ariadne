<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*, java.nio.file.*, jakarta.servlet.http.Part" %>
<%@ page import="java.util.stream.Collectors" %>
<%!
    String uploadsDir = System.getProperty("catalina.base") + "/webapps/ROOT/uploads";
%>
<%
String msg = null;
if ("POST".equals(request.getMethod())) {
    try {
        Part filePart = request.getPart("file");
        if (filePart != null && filePart.getSize() > 0) {
            String fileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
            File dir = new File(uploadsDir);
            if (!dir.exists()) dir.mkdirs();
            filePart.write(uploadsDir + File.separator + fileName);
            msg = "Uploaded: <a href='/uploads/" + fileName + "'>" + fileName + "</a>";
        }
    } catch (Exception e) {
        msg = "Upload failed: " + e.getMessage();
    }
}
%>
<!DOCTYPE html>
<html>
<head><title>Enterprise Application Server</title>
<style>
body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:0 20px}
h1{font-size:1.4em}
form{margin:20px 0;padding:16px;border:1px solid #ccc;border-radius:4px;background:#f9f9f9}
input[type=file]{margin-right:8px}
.msg{padding:8px 12px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:4px;margin-bottom:12px}
ul{list-style:none;padding:0} li{padding:4px 0}
</style>
</head>
<body>
<h1>Enterprise Application Server (JSP)</h1>
<p>Java <%= System.getProperty("java.version") %> on Apache Tomcat</p>
<% if (msg != null) { %><div class="msg"><%= msg %></div><% } %>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
</form>
<h3>Uploads</h3>
<ul>
<%
File dir = new File(uploadsDir);
if (dir.exists() && dir.isDirectory()) {
    for (File f : dir.listFiles()) {
        if (f.isFile()) {
%>
    <li><a href="/uploads/<%= f.getName() %>"><%= f.getName() %></a> (<%= f.length() %> bytes)</li>
<%
        }
    }
}
%>
</ul>
</body>
</html>
