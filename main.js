"use strict";

// Boot stuff when DOM is loaded
$(function (event) {
	console.group('App');
	console.info('DOM Loaded.', event);
	
	$(".button-collapse").sideNav();
	$('.materialboxed').materialbox();
	$('.scrollspy').scrollSpy();
	$('.parallax').parallax();
	$('.tooltipped').tooltip({delay: 50});
	$('.modal').modal({
		dismissible: true, // Modal can be dismissed by clicking outside of the modal
		opacity: .5, // Opacity of modal background
		inDuration: 300, // Transition in duration
		outDuration: 200, // Transition out duration
		startingTop: '4%', // Starting top style attribute
		endingTop: '10%', // Ending top style attribute
		ready: function(modal, trigger) { // Callback for Modal open. Modal and trigger parameters available.
			console.log('Modal -- Open', modal, trigger);
		},
		complete: function() { // Callback for Modal close
			console.log('Modal -- Close');
		}
	});
	$('.dropdown-button').dropdown({
		inDuration: 300,
		outDuration: 225,
		constrainWidth: false, // Does not change width of dropdown to that of the activator
		hover: true, // Activate on hover
		gutter: 0, // Spacing from edge
		belowOrigin: false, // Displays dropdown below the button
		alignment: 'left', // Displays dropdown with edge aligned to the left of button
		stopPropagation: false // Stops event propagation
	});
	$('.collapsible').collapsible({
		accordion: false, // A setting that changes the collapsible behavior to expandable instead of the default accordion style
		onOpen: function(el) { console.log('Collapsible -- Open', el); }, // Callback for Collapsible open
		onClose: function(el) { console.log('Collapsible -- Close', el); } // Callback for Collapsible close
	});

	// Disable click on empty links
	$('a[href="#!"]').on('click', function (event) {
		event.preventDefault();
	});

	// Toggle container
	// $('#toggle-container').on('click', function (event) {
	// 	event.preventDefault();
	// 	$('#dyn-container').toggleClass('container');
	// });

	// Display progress bar
	// $('.progress').eq(0).show('slow');

	console.groupEnd();
});