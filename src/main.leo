// The 'newsletter' program.

program newsletter_v0_1_0.aleo {

    // Struct to represent 24 bytes of data.
    struct Bytes24 {
        b0: u8,
        b1: u8,
        b2: u8,
        b3: u8,
        b4: u8,
        b5: u8,
        b6: u8,
        b7: u8,
        b8: u8,
        b9: u8,
        b10: u8,
        b11: u8,
        b12: u8,
        b13: u8,
        b14: u8,
        b15: u8,
        b16: u8,
        b17: u8,
        b18: u8,
        b19: u8,
        b20: u8,
        b21: u8,
        b22: u8,
        b23: u8,
    }

    // Struct to represent 64 bytes of data.
    struct Bytes64 {
        b0: u128,
        b1: u128,
        b2: u128,
        b3: u128,
    }

    // Struct to represent a shared secret between parties.
    struct SharedSecret {
        shared_public_key: Bytes64,
        recipient: Bytes64,
    }

    // Struct to represent a shared issue in the newsletter.
    struct SharedIssue {
        nonce: Bytes64,
        path: Bytes64,
    }

    // Record to represent a newsletter.
    record Newsletter {
        owner: address,                 // Owner of the newsletter.
        op: address,                    // Operator of the newsletter.
        id: field,                      // Unique identifier for the newsletter.
        member_sequence: field,         // Sequence number of the newsletter member.
        base: bool,                     // Flag indicating whether it's a base newsletter.
        revision: bool,                 // Flag indicating whether it's a revision of a newsletter.
        title: Bytes64,                 // Title of the newsletter.
        title_nonce: Bytes24,           // Nonce for the title.
        template: Bytes64,              // Template of the newsletter.
        template_nonce: Bytes24,        // Nonce for the template.
        content: Bytes64,               // Content of the newsletter.
        content_nonce: Bytes24,         // Nonce for the content.
        group_symmetric_key: Bytes64,   // Symmetric key for the group.
        individual_private_key: Bytes64, // Private key for individual decryption.
    }

    // Record to represent a subscription to a newsletter.
    record Subscription {
        owner: address,                 // Owner of the subscription.
        op: address,                    // Operator of the subscription.
        id: field,                      // Unique identifier for the newsletter.
        member_sequence: field,         // Sequence number of the newsletter member.
        member_secret_idx: field,       // Index of the member secret.
    }

    // Mapping to store the sequence number of newsletter members.
    mapping newsletter_member_sequence: field => field;

    // Mapping to store shared secrets between newsletter members.
    mapping member_secrets: field => SharedSecret;

    // Mapping to store the sequence number of newsletter issues.
    mapping newsletter_issue_sequence: field => field;

    // Mapping to store shared issues in the newsletter.
    mapping newsletter_issues: field => SharedIssue;

    // Functions

    // Cantor's pairing function to map two field values to a unique field value.
    function cantors_pairing(x: field, y: field) -> field {
        return (((x + y) * (x + y + 1field)) / 2field) + y;
    }

    // Check if a Bytes64 value is empty (all fields are zero).
    function is_empty_bytes64(bytes: Bytes64) -> bool {
        let bytes_a_b_equality: bool = bytes.b0 == bytes.b1;
        let empty_bytes_ab: bool = bytes_a_b_equality && bytes.b0 == 0u128;
        let bytes_c_d_equality: bool = bytes.b2 == bytes.b3;
        let empty_bytes_cd: bool = bytes_c_d_equality && bytes.b2 == 0u128;
        return empty_bytes_ab && empty_bytes_cd;
    }

    // Transitions

    // Main transition to create a new newsletter.
    transition main(
        title: Bytes64,
        title_nonce: Bytes24,
        template: Bytes64,
        template_nonce: Bytes24,
        content: Bytes64,
        content_nonce: Bytes24,
        group_symmetric_key: Bytes64,
        individual_private_key: Bytes64,
        shared_public_key: Bytes64,
        shared_recipient: Bytes64
    ) -> Newsletter {
        assert(!is_empty_bytes64(shared_public_key));
        assert(!is_empty_bytes64(shared_recipient));
        
        let idx: field = BHP256::hash_to_field(group_symmetric_key);
        let member_sequence: field = 1field;
        let member_secret_idx: field = cantors_pairing(idx, member_sequence);

        return Newsletter {
            owner: self.caller,
            op: self.caller,
            id: idx,
            member_sequence,
            base: true,
            revision: false,
            title,
            title_nonce,
            template,
            template_nonce,
            content,
            content_nonce,
            group_symmetric_key,
            individual_private_key,
        } then finalize (idx, member_sequence, member_secret_idx, shared_public_key, shared_recipient);
    }

    // Invite transition to invite a recipient to a newsletter.
    transition invite(newsletter: Newsletter, recipient: address) -> (Newsletter, Newsletter) {
        assert(newsletter.owner == self.caller);
        assert(newsletter.op == self.caller);
        assert(newsletter.base == true);
        assert(newsletter.revision == false);

        let member_id: field = newsletter.member_sequence + 1field;
        let empty_secret: Bytes64 = Bytes64 {
            b0: 0u128,
            b1: 0u128,
            b2: 0u128,
            b3: 0u128,
        };

        return (Newsletter {
            owner: self.caller,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: member_id,
            base: newsletter.base,
            revision: newsletter.revision,
            title: newsletter.title,
            title_nonce: newsletter.title_nonce,
            template: newsletter.template, 
            template_nonce: newsletter.template_nonce,
            content: newsletter.content,
            content_nonce: newsletter.content_nonce,
            group_symmetric_key: newsletter.group_symmetric_key,
            individual_private_key: newsletter.individual_private_key,
        }, Newsletter {
            owner: recipient,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: member_id,
            base: !newsletter.base,
            revision: !newsletter.revision,
            title: newsletter.title,
            title_nonce: newsletter.title_nonce,
            template: newsletter.template,
            template_nonce: newsletter.template_nonce,
            content: newsletter.content,
            content_nonce: newsletter.content_nonce,
            group_symmetric_key: newsletter.group_symmetric_key,
            individual_private_key: empty_secret,
        }) then finalize (newsletter.id, member_id);
    }

    // Accept transition to accept an invitation and join the newsletter.
    transition accept(newsletter: Newsletter, secret: Bytes64, shared_public_key: Bytes64, shared_recipient: Bytes64) -> (Newsletter, Subscription, Subscription) {
        assert(self.caller == newsletter.owner);
        assert(self.caller != newsletter.op);
        assert(newsletter.base == false);
        assert(newsletter.revision == true);
        assert(!is_empty_bytes64(shared_public_key));
        assert(!is_empty_bytes64(shared_recipient));

        let member_secret_idx: field = cantors_pairing(newsletter.id, newsletter.member_sequence);

        return (Newsletter {
            owner: self.caller,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: newsletter.member_sequence,
            base: newsletter.base,
            revision: newsletter.revision,
            title: newsletter.title,
            title_nonce: newsletter.title_nonce,
            template: newsletter.template,
            template_nonce: newsletter.template_nonce,
            content: newsletter.content,
            content_nonce: newsletter.content_nonce,
            group_symmetric_key: newsletter.group_symmetric_key,
            individual_private_key: secret,
        }, Subscription {
            owner: self.caller,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: newsletter.member_sequence,
            member_secret_idx: member_secret_idx,
        }, Subscription {
            owner: newsletter.op,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: newsletter.member_sequence,
            member_secret_idx: member_secret_idx,
        }) then finalize (member_secret_idx, shared_public_key, shared_recipient);
    }

    // Deliver transition to publish a new issue of the newsletter.
    transition deliver(newsletter: Newsletter, title: Bytes64, title_nonce: Bytes24, content: Bytes64, content_nonce: Bytes24, issue_path: Bytes64, issue_nonce: Bytes64) -> Newsletter {
        assert(newsletter.owner == self.caller);
        assert(!is_empty_bytes64(issue_path));
        assert(!is_empty_bytes64(issue_nonce));

        return Newsletter {
            owner: self.caller,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: newsletter.member_sequence,
            base: newsletter.base,
            revision: newsletter.revision,
            title: title,
            title_nonce: title_nonce,
            template: newsletter.template,
            template_nonce: newsletter.template_nonce,
            content: content,
            content_nonce: content_nonce,
            group_symmetric_key: newsletter.group_symmetric_key,
            individual_private_key: newsletter.individual_private_key,
        } then finalize (newsletter.id, issue_path, issue_nonce);
    }

    // Update transition to update the content of the newsletter.
    transition update(newsletter: Newsletter, title: Bytes64, title_nonce: Bytes24, template: Bytes64, template_nonce: Bytes24, content: Bytes64, content_nonce: Bytes24) -> Newsletter {
        assert(newsletter.owner == self.caller);
        assert(newsletter.base == true);
        assert(newsletter.revision == false);

        return Newsletter {
            owner: self.caller,
            op: newsletter.op,
            id: newsletter.id,
            member_sequence: newsletter.member_sequence,
            base: newsletter.base,
            revision: newsletter.revision,
            title,
            title_nonce,
            template,
            template_nonce,
            content,
            content_nonce,
            group_symmetric_key: newsletter.group_symmetric_key,
            individual_private_key: newsletter.individual_private_key,
        };
    }

    // Unsubscribe transition to leave the newsletter.
    transition unsub(subscription: Subscription) -> bool {
        assert(subscription.owner == self.caller || subscription.op == self.caller);

        let member_secret_idx: field = subscription.member_secret_idx;
        return subscription.owner == self.caller then finalize (member_secret_idx);
    }

    // Finalize functions

    // Finalize function for the main transition.
    finalize main(idx: field, member_sequence: field, member_secret_idx: field, shared_public_key: Bytes64, shared_recipient: Bytes64) {
        assert(member_sequence == 1field);
        assert (Mapping::contains(newsletter_member_sequence, idx) == false);
        assert(Mapping::contains(member_secrets, member_secret_idx) == false);
        Mapping::set(newsletter_member_sequence, idx, member_sequence);
        Mapping::set(member_secrets, member_secret_idx, SharedSecret {
            shared_public_key: shared_public_key,
            recipient: shared_recipient,
        });
    }

    finalize invite(idx: field, member_sequence: field) {
        assert(Mapping::contains(newsletter_member_sequence, idx) == true);
        Mapping::set(newsletter_member_sequence, idx, member_sequence);
    }

    finalize accept(member_secret_idx: field, shared_public_key: Bytes64, shared_recipient: Bytes64) {
        assert(Mapping::contains(member_secrets, member_secret_idx) == false);
        Mapping::set(member_secrets, member_secret_idx, SharedSecret {
            shared_public_key: shared_public_key,
            recipient: shared_recipient,
        });
    }

    finalize deliver(id: field, issue_path: Bytes64, issue_nonce: Bytes64) {
        let x: field = id;
        let y: field = Mapping::get_or_use(newsletter_issue_sequence, id, 0field);
        let idx: field = (((x + y) * (x + y + 1field)) / 2field) + y;
        assert(Mapping::contains(newsletter_issues, idx) == false);
        Mapping::set(newsletter_issue_sequence, id, y + 1field);
        Mapping::set(newsletter_issues, idx, SharedIssue {
            nonce: issue_nonce,
            path: issue_path,
        });
    }

    finalize unsub(member_secret_idx: field) {
        assert(Mapping::contains(member_secrets, member_secret_idx) == true);
        Mapping::remove(member_secrets, member_secret_idx);
    }
}
