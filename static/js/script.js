// Funções JavaScript globais para o site

// Validação de formulários
document.addEventListener('DOMContentLoaded', function() {
    // Validação do formulário de contato
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Validação simples
            let isValid = true;
            const inputs = contactForm.querySelectorAll('input[required], textarea[required], select[required]');
            
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.classList.add('is-invalid');
                } else {
                    input.classList.remove('is-invalid');
                }
            });
            
            if (isValid) {
                // Simulação de envio
                alert('Obrigado por entrar em contato! Retornaremos em breve.');
                contactForm.reset();
            } else {
                alert('Por favor, preencha todos os campos obrigatórios.');
            }
        });
    }
    
    // Validação do formulário de registro
    const registerForm = document.querySelector('form[action="{{ url_for(\'register\') }}"]');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password');
            const confirmPassword = document.getElementById('confirm_password');
            
            if (password.value !== confirmPassword.value) {
                e.preventDefault();
                alert('As senhas não coincidem!');
                confirmPassword.classList.add('is-invalid');
            }
        });
    }
    
    // Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Função para atualizar tickets (usada no painel do dev)
function updateTicket(ticketId, status) {
    fetch('/api/tickets/' + ticketId, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            status: status,
            dev_id: {{ session.user_id if session.user_id else 'null' }}
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert('Ticket atualizado com sucesso!');
            location.reload();
        } else {
            alert('Erro ao atualizar ticket: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Erro ao atualizar ticket.');
    });
}

// Função para criar tickets (usada no painel do cliente)
function createTicket() {
    const title = document.getElementById('ticketTitle').value;
    const description = document.getElementById('ticketDescription').value;
    
    if (!title || !description) {
        alert('Por favor, preencha todos os campos.');
        return;
    }
    
    fetch('/api/tickets', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title: title,
            description: description
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert('Chamado criado com sucesso!');
            // Fechar o modal e recarregar a página
            const modal = bootstrap.Modal.getInstance(document.getElementById('newTicketModal'));
            modal.hide();
            location.reload();
        } else {
            alert('Erro ao criar chamado: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Erro ao criar chamado.');
    });
}