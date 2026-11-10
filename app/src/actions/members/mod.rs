//! Membership use cases: list, invite, accept (bound to the invited email), remove (never the
//! last owner), list and revoke invites, change a role (never demoting the last owner).
mod accept_invite;
mod change_role;
mod invite_member;
mod list_invites;
mod list_members;
mod remove_member;
mod revoke_invite;

pub use accept_invite::AcceptInvite;
pub use change_role::ChangeRole;
pub use invite_member::InviteMember;
pub use list_invites::ListInvites;
pub use list_members::ListMembers;
pub use remove_member::RemoveMember;
pub use revoke_invite::RevokeInvite;

pub struct Members {
    pub list_members: ListMembers,
    pub invite_member: InviteMember,
    pub accept_invite: AcceptInvite,
    pub remove_member: RemoveMember,
    pub list_invites: ListInvites,
    pub revoke_invite: RevokeInvite,
    pub change_role: ChangeRole,
}
