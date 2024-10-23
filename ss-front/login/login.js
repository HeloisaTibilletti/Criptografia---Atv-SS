document.getElementById("loginForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const data = {
        email: email,
        password: password
    };

    axios.post("http://localhost:4000/login", data)
        .then((response) => {
            if (response.data.status) {
                showAlert("success", response.data.message);
                // Login bem-sucedido, redirecionar para a página de CRUD
                // window.location.href = "../crud/crud.html";
            } else {
                showAlert("danger", response.data.message);
            }
        })
        .catch((error) => {
            // Erro de conexão ou servidor
            showAlert("danger", "Erro de login. Tente novamente mais tarde.");
            console.error(error);
        });
});

document.getElementById("forgotPasswordForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const email = document.getElementById("forgotPasswordEmail").value;
    if (email) {
        console.log("Email capturado:", email); // Adicionado para verificar o valor do email
        axios.post(`http://localhost:4000/forgotPassword/${email}`)
            .then((response) => {
                // Sucesso, exibir alerta de sucesso
                showAlert("success", "E-mail de recuperação enviado!");
                console.log(response.data.message);
            })
            .catch((error) => {
                // Erro, exibir alerta de erro
                showAlert("danger", "Erro ao enviar e-mail de recuperação: " + error.response.data.error);
                console.error(error.response.data.error);
            });
    }
});

function showAlert(type, message) {
    const alertDiv = document.createElement("div");
    alertDiv.className = "alert alert-" + type;
    alertDiv.textContent = message;

    const modalBody = document.getElementById("forgotPasswordModal").querySelector(".modal-body");
    modalBody.insertBefore(alertDiv, modalBody.firstChild);

    setTimeout(() => {
        alertDiv.remove();
    }, 9000);
}