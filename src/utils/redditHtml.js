const he = require("he");

function unescapeSelfText(post) {
	// Listings wrap submissions in `data`; comment pages return the submission
	// directly. Normalize both shapes so crosspost parents are decoded too.
	const submission = post?.data || post;
	if (!submission) return;

	if (submission.selftext_html) {
		submission.selftext_html = he.decode(submission.selftext_html);
	}
	if (
		submission.crosspost_parent_list &&
		submission.crosspost_parent_list.length > 0
	) {
		unescapeSelfText(submission.crosspost_parent_list[0]);
	}
}

module.exports = { unescapeSelfText };
