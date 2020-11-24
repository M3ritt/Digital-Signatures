$(document).ready(function() {
	$('form').on('submit', function(event) {
		$.ajax({
			data : {
				new_input : $('#new_input').val(),
				original_input : $('#original_input').val(),
				first_bit_size : $('#first_bit').val(),
				second_bit_size : $('#second_bit').val()
			},
			type : 'POST',
			url : '/time_process'
		})
		.done(function(data) {
			if (data.error) {
				$('#errorAlert').text(data.error).show();
				$('#successAlert').hide();
				$('#difference').hide();
			} else {
				$('#successAlert').text(data.name).show();
				$('#first_bit_size').text(data.first_bit_size).show();
				$('#second_bit_size').text(data.second_bit_size).show();
				$('#difference').text(data.difference).show();
				$('#errorAlert').hide();
			}
		});
		event.preventDefault();
	});
});