function login() {
    let name = document.getElementById("name").value;
    let pass = document.getElementById("password").value;
    let user = {
        "name": name,
        "password": pass
    }
    $.ajax({
        headers:{
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        type: "POST",
        data: JSON.stringify(user),
        url: "http://localhost:8080/login",
        success: function (data) {
            localStorage.setItem("object", JSON.stringify(data))
            window.location.href = "../admin/index.html"
            console.log(data)
        }
    })
}