// Copyright (c) 2025, amaken and contributors
// For license information, please see license.txt

frappe.ui.form.on('Zatca Invoice Counting Settings', {
	validate: function (frm) {

		// Loop through all fields and set them to read-only
		$.each(frm.fields_dict, function (fieldname, field) {
			frm.set_df_property(fieldname, 'read_only', 1);
		});
		frm.refresh_fields();

	},
	zatca_settings_reference(frm) {
		if (frm.doc.zatca_settings_reference) {
			frappe.db.get_value('zatca amaken settings', frm.doc.zatca_settings_reference, 'integration_type')
				.then(r => {
					if (r && r.integration_type) {
						frm.set_value('integration_type', r.integration_type);
					}
				});
		}
	}
});
