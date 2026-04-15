const fileInput = document.getElementById('csvInput');

async function uploadFile() {
    const file = fileInput.files[0];
    if (!file) return alert("Please select a file first!");

    const formData = new FormData();
    formData.append("file", file); // "file" must match the parameter name in FastAPI

    const response = await fetch("http://127.0.0.1:8000/upload-csv", {
        method: "POST",
        body: formData
    });

    const result = await response.json();
    console.log(result);
}