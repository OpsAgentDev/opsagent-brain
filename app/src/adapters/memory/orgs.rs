use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    org::{
        Invite, Member, NewOrganisation, Organisation, OrganisationPatch, OrganisationsRepo, Role,
    },
    repo::{RepoError, RepoResult},
    user::Email,
};
use uuid::Uuid;

use super::{InviteRow, MemState, MemStore, MemberRow};

impl MemState {
    fn member(&self, m: &MemberRow) -> RepoResult<Member> {
        let u = self.users.iter().find(|u| u.id == m.user_id);
        let u = u.ok_or_else(|| RepoError::Storage("member without user".into()))?;
        Ok(Member {
            id: m.id,
            organisation_id: m.organisation_id,
            user_id: m.user_id,
            email: u.email.clone(),
            name: u.name.clone(),
            role: m.role,
            created_at: m.created_at,
        })
    }

    pub(super) fn org_mut(&mut self, organisation_id: Uuid) -> RepoResult<&mut Organisation> {
        let o = self.orgs.iter_mut().find(|o| o.id == organisation_id);
        o.ok_or(RepoError::NotFound)
    }

    fn live(&self, organisation_id: Uuid) -> Option<&Organisation> {
        self.orgs
            .iter()
            .find(|o| o.id == organisation_id && o.deleted_at.is_none())
    }
}

#[async_trait]
impl OrganisationsRepo for MemStore {
    async fn insert(&self, new: NewOrganisation) -> RepoResult<Organisation> {
        let mut s = self.state();
        if s.orgs.iter().any(|o| o.slug == new.slug) {
            return Err(RepoError::Conflict("slug"));
        }
        let o = Organisation {
            id: new.id,
            slug: new.slug,
            name: new.name,
            timezone: new.timezone,
            kek_version: Some(new.kek_version),
            wrapped_dek: Some(new.wrapped_dek),
            created_at: Utc::now(),
            deleted_at: None,
        };
        s.orgs.push(o.clone());
        Ok(o)
    }

    async fn get(&self, organisation_id: Uuid) -> RepoResult<Option<Organisation>> {
        Ok(self.state().org_mut(organisation_id).ok().cloned())
    }

    async fn lock(&self, _organisation_id: Uuid) -> RepoResult<()> {
        Ok(()) // a transaction already holds a private snapshot
    }

    async fn membership(
        &self,
        slug: &str,
        user_id: Uuid,
    ) -> RepoResult<Option<(Organisation, Member)>> {
        let s = self.state();
        let Some(o) = s
            .orgs
            .iter()
            .find(|o| o.slug == slug && o.deleted_at.is_none())
        else {
            return Ok(None);
        };
        let m = s
            .members
            .iter()
            .find(|m| m.organisation_id == o.id && m.user_id == user_id);
        m.map(|m| Ok((o.clone(), s.member(m)?))).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> RepoResult<Vec<(Organisation, Role)>> {
        let s = self.state();
        Ok(s.members
            .iter()
            .filter(|m| m.user_id == user_id)
            .filter_map(|m| s.live(m.organisation_id).map(|o| (o.clone(), m.role)))
            .collect())
    }

    async fn update(
        &self,
        organisation_id: Uuid,
        patch: OrganisationPatch,
    ) -> RepoResult<Organisation> {
        let mut s = self.state();
        let o = s.org_mut(organisation_id)?;
        if let Some(n) = patch.name {
            o.name = n;
        }
        if let Some(t) = patch.timezone {
            o.timezone = t;
        }
        Ok(o.clone())
    }

    async fn soft_delete(&self, organisation_id: Uuid, at: DateTime<Utc>) -> RepoResult<()> {
        self.state().org_mut(organisation_id)?.deleted_at = Some(at);
        Ok(())
    }

    async fn is_deleted(&self, organisation_id: Uuid) -> RepoResult<bool> {
        Ok(self.state().live(organisation_id).is_none())
    }

    async fn add_member(
        &self,
        organisation_id: Uuid,
        user_id: Uuid,
        role: Role,
    ) -> RepoResult<Member> {
        let mut s = self.state();
        let taken = |m: &MemberRow| m.organisation_id == organisation_id && m.user_id == user_id;
        if s.members.iter().any(taken) {
            return Err(RepoError::Conflict("member"));
        }
        let row = MemberRow {
            id: Uuid::new_v4(),
            organisation_id,
            user_id,
            role,
            created_at: Utc::now(),
        };
        let m = s.member(&row)?;
        s.members.push(row);
        Ok(m)
    }

    async fn members(&self, organisation_id: Uuid) -> RepoResult<Vec<Member>> {
        let s = self.state();
        s.members
            .iter()
            .filter(|m| m.organisation_id == organisation_id)
            .map(|m| s.member(m))
            .collect()
    }

    async fn remove_member(&self, organisation_id: Uuid, member_id: Uuid) -> RepoResult<bool> {
        let mut s = self.state();
        let at = s
            .members
            .iter()
            .position(|m| m.id == member_id && m.organisation_id == organisation_id);
        let Some(at) = at else {
            return Ok(false);
        };
        let gone = s.member(&s.members[at])?.email;
        s.members.remove(at);
        for i in &mut s.invites {
            if i.invite.organisation_id == organisation_id && i.invite.email == gone {
                i.pending = false;
            }
        }
        Ok(true)
    }

    async fn owner_count(&self, organisation_id: Uuid) -> RepoResult<u64> {
        let s = self.state();
        let owners = s
            .members
            .iter()
            .filter(|m| m.organisation_id == organisation_id && m.role == Role::Owner);
        Ok(owners.count() as u64)
    }

    async fn insert_invite(
        &self,
        organisation_id: Uuid,
        email: &Email,
        role: Role,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<Invite> {
        let invite = Invite {
            id: Uuid::new_v4(),
            organisation_id,
            email: email.clone(),
            role,
            expires_at,
            accepted_at: None,
        };
        self.state().invites.push(InviteRow {
            invite: invite.clone(),
            token_hash: token_hash.into(),
            pending: true,
        });
        Ok(invite)
    }

    async fn pending_invites(&self, organisation_id: Uuid, now: DateTime<Utc>) -> RepoResult<u64> {
        let s = self.state();
        let live = |i: &&InviteRow| {
            i.pending && i.invite.organisation_id == organisation_id && i.invite.expires_at > now
        };
        Ok(s.invites.iter().filter(live).count() as u64)
    }

    async fn take_invite(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<Invite>> {
        let mut s = self.state();
        let row = s
            .invites
            .iter_mut()
            .find(|i| i.token_hash == token_hash && i.pending && i.invite.expires_at > now);
        Ok(row.map(|i| {
            i.pending = false;
            i.invite.accepted_at = Some(now);
            i.invite.clone()
        }))
    }
}
