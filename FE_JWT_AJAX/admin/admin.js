let object = JSON.parse(localStorage.getItem("object"));
if (object != null){
    let token = object.accessToken;
    $.ajax({
        headers:{
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': "Bearer " + token
        },
        type:"GET",
        url: "http://localhost:8080/admin",
        success: function (data){
            console.log(data)
        }
    })
}
else {
    window.location.href = "../login/login.html"
}