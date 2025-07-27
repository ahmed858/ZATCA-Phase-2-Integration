// Copyright (c) 2025, ahmed and contributors
// For license information, please see license.txt

frappe.ui.form.on('Sales Invoice Additional Fields', {


	validate: function (frm) {

		$.each(frm.fields_dict, function (fieldname, field) {
			frm.set_df_property(fieldname, 'read_only', 1);
		});
		frm.refresh_fields();

	}


});
