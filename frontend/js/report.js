document.getElementById("reportForm").addEventListener("submit", function(e){
  e.preventDefault();
  const formData = new FormData(this);

  fetch("/api/report", {
    method: "POST",
    body: formData
  })
  .then(() => {
    alert("Complaint submitted!");
    window.location.href = "index.html";
  });
});