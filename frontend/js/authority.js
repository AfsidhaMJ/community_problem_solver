fetch("/api/complaints")
  .then(res => res.json())
  .then(data => {
    const body = document.getElementById("tableBody");
    data.forEach(c => {
      body.innerHTML += `
        <tr>
          <td>${c.id}</td>
          <td>${c.category}</td>
          <td>${c.authority}</td>
          <td>${c.address}</td>
          <td>${c.description}</td>
          <td><span class="status">${c.status}</span></td>
        </tr>`;
    });
  });