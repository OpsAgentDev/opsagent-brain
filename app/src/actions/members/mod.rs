//! Membership use cases: list, invite, accept (bound to the invited email), remove (never the
//! last owner).
mod accept_invite;
mod invite_member;
mod list_members;
mod remove_member;

pub use accept_invite::AcceptInvite;
pub use invite_member::InviteMember;
pub use list_members::ListMembers;
pub use remove_member::RemoveMember;

pub struct Members {
    pub list_members: ListMembers,
    pub invite_member: InviteMember,
    pub accept_invite: AcceptInvite,
    pub remove_member: RemoveMember,
}
