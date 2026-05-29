from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Optional
from datetime import datetime, timezone
from bson import ObjectId
from core.database import db
from core.auth import RoleChecker, User
from pydantic import BaseModel

router = APIRouter(prefix="/admin", dependencies=[Depends(RoleChecker(["admin"]))])

class ResolveReportRequest(BaseModel):
    action: str # "strip_verification" or "dismiss"

@router.get("/registration-requests")
async def get_registration_requests(request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    # Filter by admin's institute scoping
    query = {"status": "pending"}
    if admin.institute_id:
        query["institute_id"] = admin.institute_id
        
    pending_users = await db.users.find(query, {"_id": 0}).to_list(1000)
    return pending_users

@router.post("/registration-requests/{user_id}/approve")
async def approve_registration(user_id: str, request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    user_doc = await db.users.find_one({"user_id": user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
        
    if admin.institute_id and user_doc.get("institute_id") != admin.institute_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
        
    # Update user state
    await db.users.update_one(
        {"user_id": user_id},
        {"$set": {"status": "approved", "is_approved": True}}
    )
    
    # Create role profile if not exists
    role = user_doc.get("role")
    if role == "alumni":
        alumni_profile = {
            "user_id": user_id,
            "institute_id": user_doc["institute_id"],
            "department": user_doc["department"],
            "graduation_year": user_doc.get("graduation_year", 2026),
            "skills": [],
            "is_verified": True,
            "is_claimed": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "bio": user_doc.get("bio")
        }
        await db.alumni_profiles.update_one(
            {"user_id": user_id},
            {"$set": alumni_profile},
            upsert=True
        )
    elif role == "student":
        student_profile = {
            "user_id": user_id,
            "institute_id": user_doc["institute_id"],
            "department": user_doc["department"],
            "graduation_year": user_doc.get("graduation_year", 2026),
            "bio": user_doc.get("bio"),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.students.update_one(
            {"user_id": user_id},
            {"$set": student_profile},
            upsert=True
        )
        
    # Simulate email notification in terminal
    print("\n" + "="*50)
    print(f"SIMULATED EMAIL SENT TO: {user_doc.get('email')}")
    print(f"SUBJECT: AlumConnect Account Approved!")
    print(f"Hi {user_doc.get('name')},\nYour account has been successfully approved by the administrator.")
    print("="*50 + "\n")
    
    return {"status": "success", "message": "User registration request approved successfully"}

@router.post("/registration-requests/{user_id}/reject")
async def reject_registration(user_id: str, request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    user_doc = await db.users.find_one({"user_id": user_id})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
        
    if admin.institute_id and user_doc.get("institute_id") != admin.institute_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
        
    await db.users.update_one(
        {"user_id": user_id},
        {"$set": {"status": "rejected", "is_approved": False}}
    )
    
    # Simulate email
    print("\n" + "="*50)
    print(f"SIMULATED EMAIL SENT TO: {user_doc.get('email')}")
    print(f"SUBJECT: AlumConnect Account Application Status")
    print(f"Hi {user_doc.get('name')},\nWe regret to inform you that your registration request could not be approved at this time.")
    print("="*50 + "\n")
    
    return {"status": "success", "message": "User registration request rejected successfully"}

@router.put("/mentorship/requests/{request_id}/approve")
async def approve_mentorship_request(request_id: str, request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Mentorship request not found")
        
    # Check tenant scoping
    student = await db.users.find_one({"user_id": req_doc["student_id"]})
    if admin.institute_id and student and student.get("institute_id") != admin.institute_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
        
    await db.mentorship_requests.update_one(
        {"request_id": request_id},
        {"$set": {"admin_approval_status": "approved_by_admin"}}
    )
    return {"status": "success", "message": "Mentorship request approved by admin"}

@router.put("/mentorship/requests/{request_id}/reject")
async def reject_mentorship_request(request_id: str, request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Mentorship request not found")
        
    # Check tenant scoping
    student = await db.users.find_one({"user_id": req_doc["student_id"]})
    if admin.institute_id and student and student.get("institute_id") != admin.institute_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
        
    await db.mentorship_requests.update_one(
        {"request_id": request_id},
        {"$set": {"admin_approval_status": "rejected_by_admin", "status": "rejected"}}
    )
    return {"status": "success", "message": "Mentorship request rejected by admin"}

@router.delete("/mentorship/requests/{request_id}")
async def delete_mentorship_request(request_id: str, request: Request):
    admin = await RoleChecker(["admin"])(request)
    
    req_doc = await db.mentorship_requests.find_one({"request_id": request_id})
    if not req_doc:
        raise HTTPException(status_code=404, detail="Mentorship request not found")
        
    student = await db.users.find_one({"user_id": req_doc["student_id"]})
    if admin.institute_id and student and student.get("institute_id") != admin.institute_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
        
    await db.mentorship_requests.delete_one({"request_id": request_id})
    return {"status": "success", "message": "Mentorship request log deleted successfully"}


@router.get("/reported-posts")
async def get_reported_posts(request: Request):
    posts = await db.posts.find({"flags_count": {"$gt": 0}, "is_deleted": False}).to_list(1000)
    for p in posts:
        p["id"] = str(p["_id"])
        del p["_id"]
        if "created_at" in p and p["created_at"].tzinfo is None:
            p["created_at"] = p["created_at"].replace(tzinfo=timezone.utc)
    return posts

@router.delete("/posts/{post_id}")
async def admin_delete_post(post_id: str, request: Request):
    await db.posts.update_one(
        {"_id": ObjectId(post_id)},
        {"$set": {"is_deleted": True}}
    )
    return {"status": "success", "message": "Post soft-deleted successfully"}

@router.delete("/comments/{comment_id}")
async def admin_delete_comment(comment_id: str, request: Request):
    await db.comments.update_one(
        {"_id": ObjectId(comment_id)},
        {"$set": {"is_deleted": True}}
    )
    return {"status": "success", "message": "Comment soft-deleted successfully"}

@router.get("/false-info-reports")
async def get_false_info_reports(request: Request):
    reports = await db.profile_reports.find({"status": "pending_review"}).to_list(1000)
    for r in reports:
        r["report_id"] = r.get("report_id", str(r.get("_id")))
        if "_id" in r:
            del r["_id"]
        # Fetch reporter and target user info
        reporter = await db.users.find_one({"user_id": r["reporter_id"]}, {"_id": 0, "name": 1, "email": 1})
        target = await db.users.find_one({"user_id": r["target_alumni_id"]}, {"_id": 0, "name": 1, "email": 1})
        r["reporter"] = reporter
        r["target"] = target
    return reports

@router.post("/reports/{report_id}/resolve")
async def resolve_false_info_report(report_id: str, payload: ResolveReportRequest, request: Request):
    report = await db.profile_reports.find_one({"report_id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    action = payload.action
    if action == "strip_verification":
        # Resolve report and strip verified status
        await db.profile_reports.update_one(
            {"report_id": report_id},
            {"$set": {"status": "resolved_unverified"}}
        )
        await db.alumni_profiles.update_one(
            {"user_id": report["target_alumni_id"]},
            {"$set": {"is_verified": False, "open_to_refer": False}}
        )
    else:
        # Dismiss report
        await db.profile_reports.update_one(
            {"report_id": report_id},
            {"$set": {"status": "dismissed"}}
        )
        
    return {"status": "success", "message": f"Report resolved with action: {action}"}
