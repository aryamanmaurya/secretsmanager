from flask import render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import Project, Secret, ProjectShare, User
from app.forms import ProjectForm, TextSecretForm, ShareProjectForm
from app.utils.encryption import ProjectEncryption
from app.utils.security import log_activity, get_client_ip
from werkzeug.utils import secure_filename
import io
from datetime import datetime

from . import projects_bp

def get_all_users():
    """Get all active users except current user"""
    return User.query.filter(User.id != current_user.id, User.is_active == True).all()

def has_project_access(project, user_id, required_permission='read'):
    """Check if user has access to project with required permission"""
    if project.owner_id == user_id:
        return True

    share = ProjectShare.query.filter_by(project_id=project.id, user_id=user_id).first()
    if not share:
        return False

    if required_permission == 'write':
        return share.permission_level == 'read_write'

    return True  # For read permission, both 'read' and 'read_write' are sufficient

@projects_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_project():
    form = ProjectForm()

    if form.validate_on_submit():
        project = Project(
            name=form.name.data,
            description=form.description.data,
            owner_id=current_user.id
        )

        # Set up encryption for the project
        ProjectEncryption.setup_project_encryption(project)

        db.session.add(project)
        db.session.commit()

        log_activity(current_user.id, 'create_project', get_client_ip(), f'Created project: {project.name}')
        flash('Project created successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('projects/create_project.html', form=form)

@projects_bp.route('/<int:project_id>/add_text_secret', methods=['POST'])
@login_required
def add_text_secret(project_id):
    project = Project.query.get_or_404(project_id)

    # Check permissions
    if not has_project_access(project, current_user.id, 'write'):
        return jsonify({'error': 'Access denied'}), 403

    # Use request.form instead of form validation for simplicity
    name = request.form.get('name')
    content = request.form.get('content')

    if not name or not content:
        return jsonify({'error': 'Name and content are required'}), 400

    # Encrypt the secret content
    encrypted_content = ProjectEncryption.encrypt_secret(project, content)

    secret = Secret(
        project_id=project_id,
        name=name,
        secret_type='text',
        encrypted_content=encrypted_content
    )

    db.session.add(secret)
    db.session.commit()

    log_activity(current_user.id, 'add_text_secret', get_client_ip(),
                f'Added text secret to project: {project.name}')

    return jsonify({'success': True, 'message': 'Text secret added successfully!'})

@projects_bp.route('/<int:project_id>/upload_file', methods=['POST'])
@login_required
def upload_file_secret(project_id):
    project = Project.query.get_or_404(project_id)

    # Check permissions
    if not has_project_access(project, current_user.id, 'write'):
        return jsonify({'error': 'Access denied'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check file size (2MB limit)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset seek position

    if file_size > 2 * 1024 * 1024:
        return jsonify({'error': 'File size exceeds 2MB limit'}), 400

    # Check file extension
    allowed_extensions = {'txt', 'pem', 'key', 'crt', 'cer', 'pfx', 'p12'}
    if '.' in file.filename:
        extension = file.filename.rsplit('.', 1)[1].lower()
        if extension not in allowed_extensions:
            return jsonify({'error': 'File type not allowed'}), 400

    # Read and encrypt file data
    file_data = file.read()
    encrypted_data = ProjectEncryption.encrypt_secret(project, file_data)

    secret = Secret(
        project_id=project_id,
        name=secure_filename(file.filename),
        secret_type='file',
        file_name=secure_filename(file.filename),
        file_size=file_size,
        file_data=encrypted_data
    )

    db.session.add(secret)
    db.session.commit()

    log_activity(current_user.id, 'upload_file_secret', get_client_ip(),
                f'Uploaded file to project: {project.name}')

    return jsonify({'success': True, 'message': 'File uploaded successfully!'})

@projects_bp.route('/<int:project_id>/secrets/<int:secret_id>/download')
@login_required
def download_secret(project_id, secret_id):
    project = Project.query.get_or_404(project_id)
    secret = Secret.query.get_or_404(secret_id)

    # Check permissions
    if not has_project_access(project, current_user.id, 'read'):
        return jsonify({'error': 'Access denied'}), 403

    if secret.secret_type == 'text':
        # Decrypt text secret
        decrypted_content = ProjectEncryption.decrypt_secret(project, secret.encrypted_content)

        # Create a text file for download
        output = io.BytesIO()

        # Ensure we're writing bytes
        if isinstance(decrypted_content, str):
            decrypted_content = decrypted_content.encode('utf-8')
        output.write(decrypted_content)
        output.seek(0)

        log_activity(current_user.id, 'download_text_secret', get_client_ip(),
                    f'Downloaded text secret from project: {project.name}')

        return send_file(output, as_attachment=True, download_name=f"{secret.name}.txt",
                        mimetype='text/plain')

    else:  # file secret
        # Decrypt file data
        decrypted_data = ProjectEncryption.decrypt_secret(project, secret.file_data)

        output = io.BytesIO()

        # Ensure we're writing bytes for file data
        if isinstance(decrypted_data, str):
            decrypted_data = decrypted_data.encode('utf-8')
        output.write(decrypted_data)
        output.seek(0)

        log_activity(current_user.id, 'download_file_secret', get_client_ip(),
                    f'Downloaded file secret from project: {project.name}')

        return send_file(output, as_attachment=True, download_name=secret.file_name,
                        mimetype='application/octet-stream')

@projects_bp.route('/<int:project_id>/secrets/<int:secret_id>/view')
@login_required
def view_text_secret(project_id, secret_id):
    project = Project.query.get_or_404(project_id)
    secret = Secret.query.get_or_404(secret_id)

    # Check permissions and secret type
    if not has_project_access(project, current_user.id, 'read') or secret.secret_type != 'text':
        return jsonify({'error': 'Access denied'}), 403

    # Decrypt the secret
    decrypted_content = ProjectEncryption.decrypt_secret(project, secret.encrypted_content)

    log_activity(current_user.id, 'view_text_secret', get_client_ip(),
                f'Viewed text secret from project: {project.name}')

    return jsonify({
        'success': True,
        'name': secret.name,
        'content': decrypted_content
    })

@projects_bp.route('/<int:project_id>/secrets/<int:secret_id>/delete', methods=['DELETE'])
@login_required
def delete_secret(project_id, secret_id):
    project = Project.query.get_or_404(project_id)
    secret = Secret.query.get_or_404(secret_id)

    # Check permissions
    if not has_project_access(project, current_user.id, 'write'):
        return jsonify({'error': 'Access denied'}), 403

    db.session.delete(secret)
    db.session.commit()

    log_activity(current_user.id, 'delete_secret', get_client_ip(),
                f'Deleted secret from project: {project.name}')

    return jsonify({'success': True, 'message': 'Secret deleted successfully!'})

@projects_bp.route('/<int:project_id>')
@login_required
def view_project(project_id):
    project = Project.query.get_or_404(project_id)

    # Check if user has access to this project
    if not has_project_access(project, current_user.id):
        flash('Access denied to this project.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Get available users for sharing (only for project owner)
    available_users = []
    if project.owner_id == current_user.id:
        available_users = get_all_users()

    # Check if user has write access
    has_write_access = (project.owner_id == current_user.id or
                       ProjectShare.query.filter_by(
                           project_id=project.id,
                           user_id=current_user.id,
                           permission_level='read_write'
                       ).first() is not None)

    return render_template('projects/project_detail.html',
                         project=project,
                         available_users=available_users,
                         has_write_access=has_write_access)

@projects_bp.route('/<int:project_id>/share', methods=['POST'])
@login_required
def share_project(project_id):
    project = Project.query.get_or_404(project_id)

    # Check if user owns the project
    if project.owner_id != current_user.id:
        return jsonify({'success': False, 'error': 'Only project owner can share the project'}), 403

    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400

    data = request.get_json()
    user_id = data.get('user')
    permission_level = data.get('permission')

    if not user_id or not permission_level:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    # Check if user exists and is not the owner
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot share project with yourself'}), 400

    # Check if already shared
    existing_share = ProjectShare.query.filter_by(project_id=project_id, user_id=user_id).first()
    if existing_share:
        return jsonify({'success': False, 'error': 'Project already shared with this user'}), 400

    # Create share
    share = ProjectShare(
        project_id=project_id,
        user_id=user_id,
        permission_level=permission_level,
        shared_by=current_user.id
    )

    db.session.add(share)
    db.session.commit()

    log_activity(current_user.id, 'share_project', get_client_ip(),
                f'Shared project "{project.name}" with {user.username}')

    return jsonify({'success': True, 'message': 'Project shared successfully'})



@projects_bp.route('/<int:project_id>/secrets/<int:secret_id>/edit', methods=['PUT'])
@login_required
def edit_text_secret(project_id, secret_id):
    project = Project.query.get_or_404(project_id)
    secret = Secret.query.get_or_404(secret_id)

    # Check permissions and secret type
    if not has_project_access(project, current_user.id, 'write') or secret.secret_type != 'text':
        return jsonify({'error': 'Access denied'}), 403

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json()
    new_content = data.get('content')

    if not new_content:
        return jsonify({'error': 'Content is required'}), 400

    # Encrypt the new content
    encrypted_content = ProjectEncryption.encrypt_secret(project, new_content)

    # Update the secret
    secret.encrypted_content = encrypted_content
    secret.updated_at = datetime.utcnow()
    db.session.commit()

    log_activity(current_user.id, 'edit_text_secret', get_client_ip(),
                f'Edited text secret in project: {project.name}')

    return jsonify({'success': True, 'message': 'Secret updated successfully!'})
