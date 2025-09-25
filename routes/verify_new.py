"""
Verification routes for Tovia Organics
"""
from flask import Blueprint, render_template, jsonify
from datetime import datetime

verify_bp = Blueprint('verify', __name__)
_mongo = None  # Global reference to mongo instance

def init_verify_routes(mongo):
    global _mongo
    _mongo = mongo

    @verify_bp.route('/api/verify/<token>')
    def verify_account(token):
        """Handle account verification via email link."""
        try:
            print(f"\n=== Processing Verification Request ===")
            print(f"Token: {token}")
            
            # Find user with this verification token
            user = _mongo.db.users.find_one({
                'verification_token': token,
                'verification_expires': {'$gt': datetime.utcnow()}
            })
            
            if not user:
                print("Verification failed: Token not found or expired")
                return render_template('verify_expired.html')
            
            print(f"Found user: {user.get('email')}")
            
            # Mark account as verified
            result = _mongo.db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'verified': True,
                        'verification_token': None,
                        'verification_expires': None
                    }
                }
            )
            
            print(f"Update result: {result.modified_count} document(s) modified")
            
            # Double-check the update
            updated_user = _mongo.db.users.find_one({'_id': user['_id']})
            print(f"Verification status after update: {updated_user.get('verified', False)}")
            
            return render_template('verify_success.html')
            
        except Exception as e:
            print(f"Verification error: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return render_template('verify_expired.html')
