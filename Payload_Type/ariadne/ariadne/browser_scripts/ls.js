function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce(function(prev, cur) { return prev + cur; }, "");
        return {"plaintext": combined};
    } else if (task.completed && responses.length > 0) {
        var data;
        try {
            data = JSON.parse(responses[0]);
        } catch (error) {
            const combined = responses.reduce(function(prev, cur) { return prev + cur; }, "");
            return {"plaintext": combined};
        }

        var files = [];
        var basePath = task.display_params || ".";

        if (Array.isArray(data)) {
            files = data;
        } else if (data && data.files) {
            files = data.files;
            if (data.parent_path) basePath = data.parent_path;
        } else {
            return {"plaintext": responses[0]};
        }

        var extMap = {
            ".zip": "archive", ".7z": "archive", ".rar": "archive", ".tar": "archive",
            ".gz": "archive", ".bz2": "archive", ".xz": "archive", ".cab": "archive",
            ".iso": "diskimage", ".img": "diskimage", ".vhd": "diskimage",
            ".vhdx": "diskimage", ".vmdk": "diskimage",
            ".doc": "word", ".docx": "word", ".docm": "word", ".rtf": "word", ".odt": "word",
            ".xls": "excel", ".xlsx": "excel", ".xlsm": "excel", ".csv": "excel", ".ods": "excel",
            ".ppt": "powerpoint", ".pptx": "powerpoint", ".pptm": "powerpoint", ".odp": "powerpoint",
            ".pdf": "pdf",
            ".db": "database", ".sqlite": "database", ".mdb": "database",
            ".accdb": "database", ".sql": "database",
            ".pem": "keymaterial", ".key": "keymaterial", ".pfx": "keymaterial",
            ".p12": "keymaterial", ".cer": "keymaterial", ".crt": "keymaterial",
            ".jks": "keymaterial", ".kdbx": "keymaterial", ".ppk": "keymaterial", ".pub": "keymaterial",
            ".py": "sourcecode", ".js": "sourcecode", ".ts": "sourcecode",
            ".c": "sourcecode", ".cpp": "sourcecode", ".h": "sourcecode", ".cs": "sourcecode",
            ".java": "sourcecode", ".go": "sourcecode", ".rs": "sourcecode", ".rb": "sourcecode",
            ".php": "sourcecode", ".ps1": "sourcecode", ".sh": "sourcecode", ".bat": "sourcecode",
            ".json": "sourcecode", ".xml": "sourcecode", ".yaml": "sourcecode", ".yml": "sourcecode",
            ".html": "sourcecode", ".css": "sourcecode", ".jsp": "sourcecode", ".jspx": "sourcecode",
            ".aspx": "sourcecode", ".ashx": "sourcecode",
            ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
            ".bmp": "image", ".ico": "image", ".svg": "image", ".webp": "image",
            ".exe": "executable", ".dll": "executable", ".sys": "executable",
            ".msi": "executable", ".scr": "executable", ".com": "executable",
            ".so": "executable", ".elf": "executable"
        };

        var iconMap = {
            "archive":     {startIcon: "archive",     startIconHoverText: "Archive",       startIconColor: "goldenrod"},
            "diskimage":   {startIcon: "diskimage",   startIconHoverText: "Disk Image",    startIconColor: "goldenrod"},
            "word":        {startIcon: "word",         startIconHoverText: "Word Document", startIconColor: "cornflowerblue"},
            "excel":       {startIcon: "excel",        startIconHoverText: "Spreadsheet",   startIconColor: "darkseagreen"},
            "powerpoint":  {startIcon: "powerpoint",   startIconHoverText: "Presentation",  startIconColor: "indianred"},
            "pdf":         {startIcon: "pdf",           startIconHoverText: "PDF Document",  startIconColor: "orangered"},
            "database":    {startIcon: "database",      startIconHoverText: "Database File"},
            "keymaterial": {startIcon: "key",           startIconHoverText: "Key Material"},
            "sourcecode":  {startIcon: "code",          startIconHoverText: "Source Code",   startIconColor: "rgb(25,142,117)"},
            "image":       {startIcon: "image",         startIconHoverText: "Image File"},
            "executable":  {startIcon: "executable",    startIconHoverText: "Executable",    startIconColor: "rgb(244,67,54)"}
        };

        function getFileIcon(name, isFile) {
            if (!isFile) return {startIcon: "openFolder", startIconColor: "rgb(241,196,15)"};
            var dotIdx = name.lastIndexOf(".");
            if (dotIdx > 0) {
                var ext = name.substring(dotIdx).toLowerCase();
                if (extMap[ext] && iconMap[extMap[ext]]) return iconMap[extMap[ext]];
            }
            return {startIcon: "file"};
        }

        function formatSize(bytes) {
            if (bytes === 0) return "0 B";
            var units = ["B", "KB", "MB", "GB", "TB"];
            var i = 0;
            var val = bytes;
            while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
            return (i === 0 ? val : val.toFixed(1)) + " " + units[i];
        }

        function buildPath(name) {
            if (basePath === "." || basePath === "") return name;
            var sep = basePath.indexOf("\\") >= 0 ? "\\" : "/";
            var p = basePath.replace(/[\/\\]+$/, "");
            return p + sep + name;
        }

        var headers = [
            {plaintext: "actions", type: "button", width: 100, disableSort: true},
            {plaintext: "name", type: "string", fillWidth: true},
            {plaintext: "size", type: "size", width: 120},
            {plaintext: "permissions", type: "string", width: 100},
            {plaintext: "modified", type: "string", width: 180}
        ];

        files.sort(function(a, b) {
            if (a.is_file !== b.is_file) return a.is_file ? 1 : -1;
            return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
        });

        var rows = [];
        for (var i = 0; i < files.length; i++) {
            var entry = files[i];
            var fullPath = buildPath(entry.name);
            var icon = getFileIcon(entry.name, entry.is_file);

            var menuItems = [];
            if (!entry.is_file) {
                menuItems.push({
                    name: "List Contents",
                    type: "task",
                    startIcon: "openFolder",
                    ui_feature: "file_browser:list",
                    parameters: JSON.stringify({"path": fullPath})
                });
            }
            if (entry.is_file) {
                menuItems.push({
                    name: "Download",
                    type: "task",
                    startIcon: "download",
                    startIconColor: "lightgreen",
                    ui_feature: "file_browser:download",
                    parameters: fullPath,
                    hoverText: "Download file to Mythic"
                });
            }
            menuItems.push({
                name: "Remove",
                type: "task",
                startIcon: "delete",
                startIconColor: "rgb(244,67,54)",
                ui_feature: "file_browser:remove",
                parameters: fullPath,
                hoverText: "Remove file or directory"
            });

            rows.push({
                rowStyle: {},
                actions: {button: {name: "Actions", type: "menu", value: menuItems}},
                name: {
                    plaintext: entry.name,
                    startIcon: icon.startIcon,
                    startIconHoverText: icon.startIconHoverText || "",
                    startIconColor: icon.startIconColor || "",
                    cellStyle: {},
                    copyIcon: true
                },
                size: {plaintext: entry.is_file ? formatSize(entry.size) : "", cellStyle: {}},
                permissions: {plaintext: entry.permissions || "", cellStyle: {}},
                modified: {plaintext: entry.modify_time || "", cellStyle: {}}
            });
        }

        return {"table": [{
            headers: headers,
            rows: rows,
            title: "Listing: " + basePath
        }]};
    } else if (task.status === "processed") {
        return {"plaintext": "Waiting for response..."};
    } else {
        return {"plaintext": "No response yet from agent..."};
    }
}
