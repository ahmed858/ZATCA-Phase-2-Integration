// Copyright (c) 2025, ahmed and contributors
// For license information, please see license.txt

frappe.ui.form.on('zatca settings for tseting', {
	// refresh: function (frm) {
	// 	if (frm.doc.production_csid_errors == "None") {
	// 		// Loop through all fields and set them to read-only
	// 		$.each(frm.fields_dict, function (fieldname, field) {
	// 			frm.set_df_property(fieldname, 'read_only', 1);
	// 		});
	// 		frm.refresh_fields();
	// 	}
	// },
	generate_csr_btn: function (frm) {
		frm.set_df_property('csr_data', 'hidden', false);

		frappe.call({
			method: "zatca_amaken.zatca_help_files.csr_generator.create_csr", // This is the Python dotted path
			args: {
				ZATCA_settings_name: frm.doc.name
			},
			callback: function (r) {
				console.log(r);
				if (r.message == 1) {
					frappe.msgprint("CSR generated successfully");
					frm.reload_doc();

				} else {
					frappe.throw("Error: " + r.message);
				}
				frm.reload_doc();

			}
		});
	}
	,
	get_first_csid_btn: function (frm) {


		frappe.prompt(
			[
				{
					fieldname: 'otp',
					label: 'OTP',
					fieldtype: 'Data',
					reqd: 1
				}
			],
			function (values) {
				// values.otp now contains the OTP entered by the user
				frappe.call({
					method: 'zatca_amaken.zatca_help_files.helper.get_first_csid',
					args: {
						ZATCA_settings_name: cur_frm.doc.name,
						otp: values.otp
					},
					callback: function (r) {
						if (r.message == 1) {
							frappe.msgprint("First CSID fetched successfully.");
						}
						else {
							frappe.throw("eror while First CSID fetching.");
						}

						frm.reload_doc();

					}

				});

			}
			,
			'Enter OTP',
			'Submit'
		);




	},
	test_example_invoices_btn: function (frm) {
		// TEST E-INVOICES COMPLIANCE
		frappe.call({
			method: "zatca_amaken.zatca_help_files.helper.compliance_test_invoices",
			args: { ZATCA_settings_name: frm.doc.name },
			callback: function (r) {
				if (r != 1) {
					frappe.msgprint("Error while performing compliance test for invoices. Please check the logs for details.");
				} else {
					frappe.msgprint("Compliance test for invoices completed successfully.");
				}
				frm.reload_doc();

			},
			error: function (xhr, status, error) {
				frappe.msgprint(`Error: ${status} - ${error}`);
			}
		});




	}


	,
	generate_product_csid_btn: function (frm) {
		frappe.call({
			method: 'zatca_amaken.zatca_help_files.helper.get_production_csid',
			args: { ZATCA_settings_name: frm.doc.name }
			,
			callback: function (r) {
				if (r != 1) {
					frappe.throw("Error while get production CSID")
				}
				frm.reload_doc();

			}

		});



	}
});
