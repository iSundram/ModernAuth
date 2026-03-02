import { useState, useEffect } from 'react';
import {
  Users,
  Plus,
  Search,
  Edit,
  Trash2,
  UserPlus,
  UserMinus,
} from 'lucide-react';
import { Button, Input, Card, CardContent, CardHeader, Modal, useToast } from '../components/ui';
import { groupService, userService, type Group, type GroupMember } from '../api/services';
import type { User } from '../types';

export function GroupsPage() {
  const { showToast } = useToast();
  const [groups, setGroups] = useState<Group[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Modal states
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isMembersModalOpen, setIsMembersModalOpen] = useState(false);
  const [isAddMemberModalOpen, setIsAddMemberModalOpen] = useState(false);
  
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [groupMembers, setGroupMembers] = useState<GroupMember[]>([]);
  const [availableUsers, setAvailableUsers] = useState<User[]>([]);
  
  // Form states
  const [formData, setFormData] = useState({ name: '', description: '' });
  const [selectedUserId, setSelectedUserId] = useState('');

  const loadGroups = async () => {
    setIsLoading(true);
    try {
      const response = await groupService.list();
      setGroups(response.groups || []);
    } catch (error) {
      console.error('Failed to load groups:', error);
      showToast({ title: 'Failed to load groups', type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadGroups();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredGroups = groups.filter(group =>
    group.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    group.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleCreate = async () => {
    try {
      await groupService.create(formData);
      showToast({ title: 'Group created successfully', type: 'success' });
      setIsCreateModalOpen(false);
      setFormData({ name: '', description: '' });
      loadGroups();
    } catch (error) {
      console.error('Failed to create group:', error);
      showToast({ title: 'Failed to create group', type: 'error' });
    }
  };

  const handleUpdate = async () => {
    if (!selectedGroup) return;
    try {
      await groupService.update(selectedGroup.id, formData);
      showToast({ title: 'Group updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedGroup(null);
      setFormData({ name: '', description: '' });
      loadGroups();
    } catch (error) {
      console.error('Failed to update group:', error);
      showToast({ title: 'Failed to update group', type: 'error' });
    }
  };

  const handleDelete = async () => {
    if (!selectedGroup) return;
    try {
      await groupService.delete(selectedGroup.id);
      showToast({ title: 'Group deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedGroup(null);
      loadGroups();
    } catch (error) {
      console.error('Failed to delete group:', error);
      showToast({ title: 'Failed to delete group', type: 'error' });
    }
  };

  const openEditModal = (group: Group) => {
    setSelectedGroup(group);
    setFormData({ name: group.name, description: group.description || '' });
    setIsEditModalOpen(true);
  };

  const openMembersModal = async (group: Group) => {
    setSelectedGroup(group);
    try {
      const response = await groupService.listMembers(group.id);
      setGroupMembers(response.members || []);
      setIsMembersModalOpen(true);
    } catch (error) {
      console.error('Failed to load members:', error);
      showToast({ title: 'Failed to load members', type: 'error' });
    }
  };

  const openAddMemberModal = async () => {
    try {
      const users = await userService.list();
      const memberIds = new Set(groupMembers.map(m => m.user_id));
      setAvailableUsers(users.filter(u => !memberIds.has(u.id)));
      setIsAddMemberModalOpen(true);
    } catch (error) {
      console.error('Failed to load users:', error);
      showToast({ title: 'Failed to load users', type: 'error' });
    }
  };

  const handleAddMember = async () => {
    if (!selectedGroup || !selectedUserId) return;
    try {
      await groupService.addMember(selectedGroup.id, selectedUserId);
      showToast({ title: 'Member added successfully', type: 'success' });
      setIsAddMemberModalOpen(false);
      setSelectedUserId('');
      // Refresh members
      const response = await groupService.listMembers(selectedGroup.id);
      setGroupMembers(response.members || []);
      loadGroups(); // Refresh counts
    } catch (error) {
      console.error('Failed to add member:', error);
      showToast({ title: 'Failed to add member', type: 'error' });
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!selectedGroup) return;
    try {
      await groupService.removeMember(selectedGroup.id, userId);
      showToast({ title: 'Member removed successfully', type: 'success' });
      const response = await groupService.listMembers(selectedGroup.id);
      setGroupMembers(response.members || []);
      loadGroups(); // Refresh counts
    } catch (error) {
      console.error('Failed to remove member:', error);
      showToast({ title: 'Failed to remove member', type: 'error' });
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Groups</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Organize users into groups for easier management
          </p>
        </div>
        <Button onClick={() => setIsCreateModalOpen(true)} leftIcon={<Plus size={16} />}>
          Create Group
        </Button>
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--color-text-muted)]" />
          <Input
            type="text"
            placeholder="Search groups..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Groups Grid */}
      {isLoading ? (
        <div className="text-center py-12 text-[var(--color-text-muted)]">Loading...</div>
      ) : filteredGroups.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Users className="w-12 h-12 mx-auto mb-4 text-[var(--color-text-muted)]" />
            <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
              {searchQuery ? 'No groups found' : 'No groups yet'}
            </h3>
            <p className="text-[var(--color-text-secondary)] mb-4">
              {searchQuery ? 'Try adjusting your search' : 'Create your first group to get started'}
            </p>
            {!searchQuery && (
              <Button onClick={() => setIsCreateModalOpen(true)} leftIcon={<Plus size={16} />}>
                Create Group
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filteredGroups.map((group) => (
            <Card key={group.id} className="hover:border-[var(--color-border)] transition-colors">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-[var(--color-primary-dark)] flex items-center justify-center">
                      <Users size={20} className="text-[#D4D4D4]" />
                    </div>
                    <div>
                      <h3 className="font-medium text-[var(--color-text-primary)]">{group.name}</h3>
                      <p className="text-sm text-[var(--color-text-muted)]">
                        {group.member_count ?? 0} members
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <button
                      onClick={() => openMembersModal(group)}
                      className="p-2 rounded-lg hover:bg-[var(--color-light)] text-[var(--color-text-secondary)]"
                      title="Manage members"
                    >
                      <UserPlus size={16} />
                    </button>
                    <button
                      onClick={() => openEditModal(group)}
                      className="p-2 rounded-lg hover:bg-[var(--color-light)] text-[var(--color-text-secondary)]"
                      title="Edit group"
                    >
                      <Edit size={16} />
                    </button>
                    <button
                      onClick={() => { setSelectedGroup(group); setIsDeleteModalOpen(true); }}
                      className="p-2 rounded-lg hover:bg-[var(--color-error)]/10 text-[var(--color-error)]"
                      title="Delete group"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </CardHeader>
              {group.description && (
                <CardContent>
                  <p className="text-sm text-[var(--color-text-secondary)]">{group.description}</p>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Create Group Modal */}
      <Modal isOpen={isCreateModalOpen} onClose={() => setIsCreateModalOpen(false)} title="Create Group">
        <div className="space-y-4">
          <Input
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="Enter group name"
          />
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Optional description"
              rows={3}
              className="w-full px-4 py-2.5 rounded-xl border border-[var(--color-border)] bg-white text-[var(--color-text-primary)] focus:border-[var(--color-medium)] focus:outline-none"
            />
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsCreateModalOpen(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={!formData.name}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Edit Group Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Group">
        <div className="space-y-4">
          <Input
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="Enter group name"
          />
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Optional description"
              rows={3}
              className="w-full px-4 py-2.5 rounded-xl border border-[var(--color-border)] bg-white text-[var(--color-text-primary)] focus:border-[var(--color-medium)] focus:outline-none"
            />
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsEditModalOpen(false)}>Cancel</Button>
            <Button onClick={handleUpdate} disabled={!formData.name}>Save Changes</Button>
          </div>
        </div>
      </Modal>

      {/* Delete Group Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Group">
        <div className="space-y-4">
          <p className="text-[var(--color-text-secondary)]">
            Are you sure you want to delete <strong>{selectedGroup?.name}</strong>? This action cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsDeleteModalOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={handleDelete}>Delete</Button>
          </div>
        </div>
      </Modal>

      {/* Members Modal */}
      <Modal isOpen={isMembersModalOpen} onClose={() => setIsMembersModalOpen(false)} title={`Members of ${selectedGroup?.name}`} size="lg">
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <p className="text-[var(--color-text-secondary)]">
              {groupMembers.length} member{groupMembers.length !== 1 ? 's' : ''}
            </p>
            <Button size="sm" onClick={openAddMemberModal} leftIcon={<UserPlus size={14} />}>
              Add Member
            </Button>
          </div>
          
          {groupMembers.length === 0 ? (
            <div className="text-center py-8 text-[var(--color-text-muted)]">
              No members in this group yet
            </div>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {groupMembers.map((member) => (
                <div
                  key={member.user_id}
                  className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border-light)]"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-[var(--color-primary-dark)] flex items-center justify-center text-white text-sm">
                      {member.user?.username?.charAt(0).toUpperCase() || '?'}
                    </div>
                    <div>
                      <p className="font-medium text-[var(--color-text-primary)]">
                        {member.user?.username || member.user_id}
                      </p>
                      {member.user?.email && (
                        <p className="text-sm text-[var(--color-text-muted)]">{member.user.email}</p>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRemoveMember(member.user_id)}
                    className="p-2 rounded-lg hover:bg-[var(--color-error)]/10 text-[var(--color-error)]"
                    title="Remove member"
                  >
                    <UserMinus size={16} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Modal>

      {/* Add Member Modal */}
      <Modal isOpen={isAddMemberModalOpen} onClose={() => setIsAddMemberModalOpen(false)} title="Add Member">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Select User
            </label>
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl border border-[var(--color-border)] bg-white text-[var(--color-text-primary)] focus:border-[var(--color-medium)] focus:outline-none"
            >
              <option value="">Choose a user...</option>
              {availableUsers.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username || user.email}
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsAddMemberModalOpen(false)}>Cancel</Button>
            <Button onClick={handleAddMember} disabled={!selectedUserId}>Add Member</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
