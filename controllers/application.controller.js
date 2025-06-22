import Application from '../models/Application.js';
import User from '../models/User.js';

// Create a new job application
export const createApplication = async (req, res) => {
  try {
    const userId = req.user.id;
    const applicationData = req.body;

    // Create the application
    const application = new Application({
      ...applicationData,
      appliedAt: new Date()
    });

    // Add initial status to status history
    application.statusHistory.push({
      status: application.currentStatus,
      updatedAt: new Date(),
      updatedBy: userId,
      note: 'Application created'
    });

    await application.save();

    // Add application reference to user
    await User.findByIdAndUpdate(
      userId,
      { $push: { applications: application._id } }
    );

    res.status(201).json({
      success: true,
      message: 'Application created successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating application',
      error: error.message
    });
  }
};

// Get all applications for a user
export const getUserApplications = async (req, res) => {
  try {
    const userId = req.user.id;
    const { status, company, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

    // Build filter object
    const filter = {};
    if (status) filter.currentStatus = status;
    if (company) filter.company = { $regex: company, $options: 'i' };


    const user = await User.findById(userId).populate({
      path: 'applications',
      match: filter,
      options: {
        sort: { [sortBy]: sortOrder === 'desc' ? -1 : 1 }
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user.applications,
      count: user.applications.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching applications',
      error: error.message
    });
  }
};

// Get single application by ID
export const getApplicationById = async (req, res) => {
  try {
    const { applicationId } = req.params;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Not found'
      });
    }

    const application = await Application.findById(applicationId);

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    res.status(200).json({
      success: true,
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching application',
      error: error.message
    });
  }
};

// Update application status
export const updateApplicationStatus = async (req, res) => {
  try {
    const { applicationId } = req.body;
    const { status, note } = req.body;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findById(applicationId);
    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }


    application.currentStatus = status;
    application.statusHistory.push({
      status,
      updatedAt: new Date(),
      updatedBy: userId,
      note: note || `Status updated to ${status}`
    });
    application.updatedAt = new Date();

    await application.save();

    res.status(200).json({
      success: true,
      message: 'Application status updated successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating application status',
      error: error.message
    });
  }
};

// Update application details
export const updateApplication = async (req, res) => {
  try {
    const { applicationId } = req.body;
    const updateData = req.body;
    const userId = req.user.id;

    // Verify user owns this application
    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    // Remove sensitive fields that shouldn't be updated directly
    delete updateData.statusHistory;
    delete updateData.createdAt;

    updateData.updatedAt = new Date();

    const application = await Application.findByIdAndUpdate(
      applicationId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Application updated successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating application',
      error: error.message
    });
  }
};

// Delete application
export const deleteApplication = async (req, res) => {
  try {
    const { applicationId } = req.params;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findByIdAndDelete(applicationId);
    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }


    await User.findByIdAndUpdate(
      userId,
      { $pull: { applications: applicationId } }
    );

    res.status(200).json({
      success: true,
      message: 'Application deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting application',
      error: error.message
    });
  }
};



// Add notes to application
export const addNotes = async (req, res) => {
  try {
    const { applicationId } = req.body;
    const { notes } = req.body;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findByIdAndUpdate(
      applicationId,
      {
        notes,
        updatedAt: new Date()
      },
      { new: true }
    );

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Notes updated successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating notes',
      error: error.message
    });
  }
};



//Reminder Handling
export const addReminder = async (req, res) => {
  try {
    const { applicationId } = req.body;
    const { dueDate, title } = req.body;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findById(applicationId);
    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    // Set the single reminder object
    application.reminders = {
      dueDate: new Date(dueDate),
      title,
      isCompleted: false
    };
    application.updatedAt = new Date();

    await application.save();

    res.status(200).json({
      success: true,
      message: 'Reminder added successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error adding reminder',
      error: error.message
    });
  }
};


export const getUserReminders = async (req, res) => {
  try {
    const userId = req.user.id;
    const { completed, upcoming, overdue } = req.query;

    const user = await User.findById(userId).populate('applications');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const currentDate = new Date();
    let allReminders = [];

    // Extract reminders from applications
    user.applications.forEach(app => {
      if (app.reminders && app.reminders.dueDate) {
        allReminders.push({
          _id: app._id,
          ...app.reminders.toObject(),
          application: {
            _id: app._id,
            jobTitle: app.jobTitle,
            company: app.company
          }
        });
      }
    });

    // Filtering logic
    if (completed === 'true') {
      allReminders = allReminders.filter(r => r.isCompleted);
    } else if (completed === 'false') {
      allReminders = allReminders.filter(r => !r.isCompleted);
    }

    if (upcoming === 'true') {
      allReminders = allReminders.filter(r =>
        !r.isCompleted && new Date(r.dueDate) > currentDate
      );
    }

    if (overdue === 'true') {
      allReminders = allReminders.filter(r =>
        !r.isCompleted && new Date(r.dueDate) < currentDate
      );
    }

    allReminders.sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate));

    return res.status(200).json({
      success: true,
      data: allReminders,
      count: allReminders.length,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching reminders',
      error: error.message,
    });
  }
};



// Update reminder completion status
export const updateReminderStatus = async (req, res) => {
  try {
    const { applicationId } = req.body;
    const { isCompleted } = req.body;
    const userId = req.user.id;


    const user = await User.findById(userId);
    if (!user.applications.includes(applicationId)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this application'
      });
    }

    const application = await Application.findById(applicationId);
    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    if (!application.reminders || !application.reminders.dueDate) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found'
      });
    }

    application.reminders.isCompleted = isCompleted;
    application.updatedAt = new Date();

    await application.save();

    res.status(200).json({
      success: true,
      message: 'Reminder status updated successfully',
      data: application
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating reminder status',
      error: error.message
    });
  }
};


