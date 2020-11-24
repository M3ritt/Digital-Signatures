$(document).ready(function() {
	$('form').on('submit', function(event) {
		$.ajax({
			data : {
				new_input : $('#new_input').val(),
				original_input : $('#original_input').val(),
				first_bit_size : $('#first_bit').val()
			},
			type : 'POST',
			url : '/process'
		})
		.done(function(data) {
			if (data.error) {
				$('#errorAlert').text(data.error).show();
				$('#successAlert').hide();
				$('#publicKeyAlert').hide();
				$('#privateKeyAlert').hide();
				$('#originalSignatureAlert').hide();
				$('#newSignatureAlert').hide();
			} else {
				$('#successAlert').text(data.name).show();
				$('#first_bit_size').text(data.first_bit_size).show();
				$('#publicKeyAlert').text(data.publicKey).show();
				$('#privateKeyAlert').text(data.privateKey).show();
				$('#originalSignatureAlert').text(data.originalSignature).show();
				$('#newSignatureAlert').text(data.newSignature).show();
				$('#errorAlert').hide();
			}
		});
		event.preventDefault();
	});
});