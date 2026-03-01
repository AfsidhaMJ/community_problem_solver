fetch("/api/stats")
  .then(res => res.json())
  .then(data => {
    document.getElementById("total").innerText = data.total;
    document.getElementById("submitted").innerText = data.submitted;
  });