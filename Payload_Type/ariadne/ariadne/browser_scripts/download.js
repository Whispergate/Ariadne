function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce(function(prev, cur) { return prev + cur; }, "");
        return {"plaintext": combined};
    } else if (task.completed) {
        if (responses.length > 0) {
            for (var i = responses.length - 1; i >= 0; i--) {
                try {
                    var data = JSON.parse(responses[i]);
                    if (data["agent_file_id"]) {
                        return {"download": [{
                            "agent_file_id": data["agent_file_id"],
                            "variant": "contained",
                            "name": data["filename"] || task.display_params || "Download",
                        }]};
                    }
                } catch (error) {}
            }
            var combined = responses.reduce(function(prev, cur) { return prev + cur; }, "");
            return {"plaintext": combined};
        }
        return {"plaintext": "Download complete"};
    } else if (task.status === "processed") {
        if (responses.length > 0) {
            return {"plaintext": responses[0]};
        }
        return {"plaintext": "Downloading..."};
    } else {
        return {"plaintext": "No response yet from agent..."};
    }
}
