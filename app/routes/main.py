from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import Project, ProjectShare, ActivityLog, Secret, User
from app.utils.security import log_activity, get_client_ip

from . import main_bp

@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    active_tab = request.args.get('tab', 'my-projects')
    
    owned_projects = Project.query.filter_by(owner_id=current_user.id).order_by(Project.created_at.desc()).all()
    
    share_records_with_me = ProjectShare.query.filter_by(user_id=current_user.id).all()
    shared_projects = [{
        'project': share.project,
        'permission': share.permission_level,
        'shared_by': User.query.get(share.shared_by),
        'shared_at': share.shared_at
    } for share in share_records_with_me]
    
    share_records_by_me = ProjectShare.query.filter_by(shared_by=current_user.id).all()
    shared_by_me = [{
        'project': share.project,
        'user': User.query.get(share.user_id),
        'permission': share.permission_level,
        'shared_at': share.shared_at,
        'share_id': share.id
    } for share in share_records_by_me]
    
    recent_activity = ActivityLog.query.filter_by(user_id=current_user.id).order_by(
        ActivityLog.timestamp.desc()
    ).limit(50).all()

    return render_template('main/dashboard.html',
                         active_tab=active_tab,
                         owned_projects=owned_projects,
                         shared_projects=shared_projects,
                         shared_by_me=shared_by_me,
                         recent_activity=recent_activity)



@main_bp.route('/get_project_secrets/<int:project_id>')
@login_required
def get_project_secrets(project_id):
    """Get secrets for a specific project (AJAX endpoint)"""
    project = Project.query.get_or_404(project_id)

    # Check if user has access to this project
    if project.owner_id != current_user.id and not ProjectShare.query.filter_by(
        project_id=project_id, user_id=current_user.id
    ).first():
        return jsonify({'error': 'Access denied'}), 403

    secrets = Secret.query.filter_by(project_id=project_id).all()
    secret_list = []
    for secret in secrets:
        secret_list.append({
            'id': secret.id,
            'name': secret.name,
            'type': secret.secret_type,
            'file_name': secret.file_name,
            'file_size': secret.file_size,
            'created_at': secret.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': secret.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    log_activity(current_user.id, 'view_project', get_client_ip(), f'Viewed project: {project.name}')

    return jsonify({
        'project_name': project.name,
        'secrets': secret_list
    })

@main_bp.route('/unshare_project/<int:share_id>', methods=['DELETE'])
@login_required
def unshare_project(share_id):
    """Unshare a project that was shared by the current user"""
    share = ProjectShare.query.get_or_404(share_id)
    
    # Check if current user is the one who shared this project
    if share.shared_by != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    # Get the project name and username using the correct relationships
    project_name = share.project.name
    # Use shared_user relationship instead of user
    username = share.shared_user.username
    
    db.session.delete(share)
    db.session.commit()
    
    log_activity(current_user.id, 'unshare_project', get_client_ip(),
                f'Unshared project "{project_name}" with {username}')
    
    return jsonify({'success': True, 'message': 'Project unshared successfully'})
